//! Logic-analyzer-assisted baud detection via sigrok-cli.
//!
//! Captures raw line samples and computes baud from the narrowest pulse:
//! `baud = samplerate / shortest_same_level_run` (the bit period). The sample
//! math is exact and unit-tested; the capture step shells out to `sigrok-cli`
//! and needs a supported analyzer connected to the RX line.

use std::error::Error;
use std::process::Command;

use colored::*;

const STANDARD_BAUDS: &[u32] = &[
    300, 1200, 2400, 4800, 9600, 14400, 19200, 38400, 57600, 115200, 230400, 460800, 921600,
    1_000_000, 1_500_000, 2_000_000, 3_000_000,
];

/// Snap a raw computed baud to the nearest standard rate, if within 10%.
pub fn snap_to_standard(raw: u32) -> Option<u32> {
    STANDARD_BAUDS
        .iter()
        .copied()
        .min_by_key(|&b| (b as i64 - raw as i64).unsigned_abs())
        .filter(|&b| (b as f64 - raw as f64).abs() / (b as f64) < 0.10)
}

/// Compute baud from line-level samples (LSB = level) and the sample rate.
/// Uses the shortest constant-level run as the bit period; the first and last
/// (possibly partial) runs are ignored when there are enough runs.
pub fn baud_from_samples(samples: &[u8], samplerate: u64) -> Option<u32> {
    if samples.len() < 4 || samplerate == 0 {
        return None;
    }
    let level = |b: u8| b & 1;
    let mut runs = Vec::new();
    let mut cur = level(samples[0]);
    let mut len = 1u64;
    for &s in &samples[1..] {
        let b = level(s);
        if b == cur {
            len += 1;
        } else {
            runs.push(len);
            cur = b;
            len = 1;
        }
    }
    runs.push(len);
    let usable = if runs.len() >= 3 {
        &runs[1..runs.len() - 1]
    } else {
        &runs[..]
    };
    let min = usable.iter().copied().filter(|&l| l > 0).min()?;
    let raw = (samplerate / min) as u32;
    Some(snap_to_standard(raw).unwrap_or(raw))
}

fn parse_csv_samples(text: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let field = line.rsplit(',').next().unwrap_or(line).trim();
        match field {
            "0" => v.push(0),
            "1" => v.push(1),
            _ => {}
        }
    }
    v
}

/// Capture from a sigrok-supported analyzer and derive the baud. Requires
/// `sigrok-cli` in PATH and a device on `driver` with the RX line on `channel`.
pub fn capture_and_detect(
    driver: &str,
    samplerate: u64,
    num_samples: u64,
    channel: &str,
) -> Result<u32, Box<dyn Error>> {
    if Command::new("sigrok-cli").arg("--version").output().is_err() {
        return Err("sigrok-cli not found in PATH".into());
    }
    println!(
        "{} capturing {} samples @ {} Hz on {} channel {}",
        "[*]".cyan(),
        num_samples,
        samplerate,
        driver,
        channel
    );
    let out = Command::new("sigrok-cli")
        .args([
            "-d",
            driver,
            "--config",
            &format!("samplerate={}", samplerate),
            "--samples",
            &num_samples.to_string(),
            "-C",
            channel,
            "-O",
            "csv",
        ])
        .output()?;
    if !out.status.success() {
        return Err(format!("sigrok-cli failed: {}", String::from_utf8_lossy(&out.stderr)).into());
    }
    let samples = parse_csv_samples(&String::from_utf8_lossy(&out.stdout));
    if samples.is_empty() {
        return Err("no samples parsed from sigrok-cli output".into());
    }
    baud_from_samples(&samples, samplerate).ok_or_else(|| "could not derive baud from samples".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snap_standard_rates() {
        assert_eq!(snap_to_standard(115000), Some(115200));
        assert_eq!(snap_to_standard(9600), Some(9600));
        assert_eq!(snap_to_standard(50), None);
    }

    #[test]
    fn baud_from_synthetic_samples() {
        // bit period 10 samples, samplerate 1_152_000 -> 115200 baud
        let mut s = vec![1u8; 20];
        s.extend_from_slice(&[0u8; 20]);
        s.extend_from_slice(&[1u8; 10]);
        s.extend_from_slice(&[0u8; 20]);
        s.extend_from_slice(&[1u8; 20]);
        assert_eq!(baud_from_samples(&s, 1_152_000), Some(115200));
    }

    #[test]
    fn csv_parsing() {
        let csv = "; comment\n0\n0\n1\n1\n0\n";
        assert_eq!(parse_csv_samples(csv), vec![0, 0, 1, 1, 0]);
    }
}
