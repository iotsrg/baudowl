// Power analysis trace capture via Bus Pirate 5 ADC.
//
// BP5 has a built-in ADC on the AUX pin. Text-mode command `d`
// returns a voltage reading. Rapid sampling during crypto operations
// or boot sequences can reveal power consumption patterns for SPA/DPA.

use std::error::Error;
use std::io::{self};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use colored::*;

use crate::ui;

const BP5_BAUD: u32 = 115200;

pub struct PowerTraceOpts {
    pub duration_ms: u64,
    pub trigger_cmd: Option<String>,
    pub out_path: String,
}

impl Default for PowerTraceOpts {
    fn default() -> Self {
        Self {
            duration_ms: 1000,
            trigger_cmd: None,
            out_path: "power_trace.csv".to_string(),
        }
    }
}

pub struct TraceSample {
    pub time_us: u64,
    pub voltage: f32,
}

fn bp_send(port: &mut dyn serialport::SerialPort, cmd: &str) -> io::Result<String> {
    port.write_all(cmd.as_bytes())?;
    port.write_all(b"\r\n")?;
    port.flush()?;
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 4096];
    let mut out = Vec::new();
    let deadline = Instant::now() + Duration::from_millis(200);
    while Instant::now() < deadline {
        match port.read(&mut buf) {
            Ok(n) if n > 0 => out.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    Ok(String::from_utf8_lossy(&out).to_string())
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_esc = false;
    for c in s.chars() {
        if in_esc {
            if c.is_ascii_alphabetic() {
                in_esc = false;
            }
            continue;
        }
        if c == '\x1b' {
            in_esc = true;
            continue;
        }
        out.push(c);
    }
    out
}

fn parse_voltage(resp: &str) -> Option<f32> {
    let clean = strip_ansi(resp);
    // BP5 ADC response format: "X.XXV" or "X.XX V"
    for word in clean.split_whitespace() {
        let trimmed = word.trim_end_matches('V').trim_end_matches('v');
        if let Ok(v) = trimmed.parse::<f32>() {
            if (0.0..=6.0).contains(&v) {
                return Some(v);
            }
        }
    }
    None
}

pub fn power_trace(
    port_path: &str,
    opts: &PowerTraceOpts,
    running: Arc<AtomicBool>,
) -> Result<Vec<TraceSample>, Box<dyn Error>> {
    ui::section("=== POWER TRACE (Bus Pirate 5 ADC) ===");
    println!("{} {}", "Port:".cyan(), port_path);
    println!(
        "{} {}ms capture -> {}",
        "Config:".cyan(),
        opts.duration_ms,
        opts.out_path
    );

    let mut port = serialport::new(port_path, BP5_BAUD)
        .timeout(Duration::from_millis(200))
        .open()
        .map_err(|e| format!("open {}: {}", port_path, e))?;

    // Reset to HiZ
    bp_send(&mut *port, "#")?;
    std::thread::sleep(Duration::from_millis(500));

    // Send trigger command if set (e.g., a command that starts a crypto op)
    if let Some(ref cmd) = opts.trigger_cmd {
        ui::step("PWR", &format!("sending trigger: {}", cmd));
        bp_send(&mut *port, cmd)?;
    }

    ui::step("PWR", "sampling ADC");
    let mut samples = Vec::new();
    let start = Instant::now();
    let deadline = start + Duration::from_millis(opts.duration_ms);

    while Instant::now() < deadline {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        let resp = bp_send(&mut *port, "d")?;
        let elapsed = start.elapsed();

        if let Some(v) = parse_voltage(&resp) {
            samples.push(TraceSample {
                time_us: elapsed.as_micros() as u64,
                voltage: v,
            });
        }
    }

    // Write CSV
    let mut csv = String::from("time_us,voltage\n");
    for s in &samples {
        csv.push_str(&format!("{},{:.4}\n", s.time_us, s.voltage));
    }
    std::fs::write(&opts.out_path, &csv)?;

    if samples.is_empty() {
        ui::warn("no ADC samples captured (check BP5 connection)");
    } else {
        let min_v = samples.iter().map(|s| s.voltage).fold(f32::MAX, f32::min);
        let max_v = samples.iter().map(|s| s.voltage).fold(f32::MIN, f32::max);
        let avg_v: f32 = samples.iter().map(|s| s.voltage).sum::<f32>() / samples.len() as f32;
        ui::win(
            "POWER TRACE",
            &format!(
                "{} samples, {:.3}V min / {:.3}V avg / {:.3}V max -> {}",
                samples.len(),
                min_v,
                avg_v,
                max_v,
                opts.out_path,
            ),
        );
    }

    Ok(samples)
}

// ── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_voltage_formats() {
        assert_eq!(parse_voltage("3.30V"), Some(3.30));
        assert_eq!(parse_voltage("  1.80 V "), Some(1.80));
        assert_eq!(parse_voltage("garbage"), None);
        assert_eq!(parse_voltage("99.9V"), None); // out of range
    }

    #[test]
    fn strip_ansi_cleans() {
        assert_eq!(strip_ansi("\x1b[32m3.3V\x1b[0m"), "3.3V");
    }

    #[test]
    fn csv_format() {
        let samples = vec![
            TraceSample { time_us: 0, voltage: 3.300 },
            TraceSample { time_us: 1000, voltage: 3.295 },
        ];
        let mut csv = String::from("time_us,voltage\n");
        for s in &samples {
            csv.push_str(&format!("{},{:.4}\n", s.time_us, s.voltage));
        }
        assert!(csv.contains("0,3.3000"));
        assert!(csv.contains("1000,3.2950"));
    }
}
