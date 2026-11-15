//! Bus Pirate 5 (RP2040) integration for baudowl.
//!
//! Configures a Bus Pirate 5 as a UART bridge over its USB CDC port.
//! After setup, the BP5 transparently forwards data between its IO pins
//! and the USB serial port, so all baudowl UART operations work through
//! it. Also provides power supply control, pull-up configuration, and
//! voltage measurement for the target device.
//!
//! Protocol: text-mode command interface over USB CDC (/dev/ttyACMx).
//! The BP5 terminal uses VT100/ANSI escape codes which we strip.

use std::error::Error;
use std::io::{self};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use colored::*;

use crate::ui;

// ── ANSI escape stripping ───────────────────────────────────────────────

fn strip_ansi(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == 0x1b {
            i += 1;
            if i < raw.len() && raw[i] == b'[' {
                i += 1;
                while i < raw.len() && !(0x40..=0x7e).contains(&raw[i]) {
                    i += 1;
                }
                if i < raw.len() {
                    i += 1;
                }
            } else if i < raw.len() {
                i += 1;
            }
        } else if raw[i] >= 0x20 || raw[i] == b'\n' || raw[i] == b'\r' || raw[i] == b'\t' {
            out.push(raw[i]);
            i += 1;
        } else {
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

// ── low-level text protocol ─────────────────────────────────────────────

fn port_drain(port: &mut dyn serialport::SerialPort, ms: u64) {
    let deadline = Instant::now() + Duration::from_millis(ms);
    let mut junk = [0u8; 256];
    while Instant::now() < deadline {
        match port.read(&mut junk) {
            Ok(_) => {}
            Err(_) => break,
        }
    }
}

fn port_read_until(
    port: &mut dyn serialport::SerialPort,
    patterns: &[&str],
    timeout: Duration,
) -> io::Result<(usize, String)> {
    let deadline = Instant::now() + timeout;
    let mut raw = Vec::with_capacity(512);
    let mut buf = [0u8; 64];
    loop {
        if Instant::now() >= deadline {
            let cleaned = strip_ansi(&raw);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "BP5: timeout waiting for {:?} (got: {})",
                    patterns,
                    if cleaned.len() > 120 { &cleaned[cleaned.len()-120..] } else { &cleaned }
                ),
            ));
        }
        match port.read(&mut buf) {
            Ok(n) if n > 0 => {
                raw.extend_from_slice(&buf[..n]);
                let cleaned = strip_ansi(&raw);
                let lower = cleaned.to_ascii_lowercase();
                for (i, pat) in patterns.iter().enumerate() {
                    if lower.contains(&pat.to_ascii_lowercase()) {
                        return Ok((i, cleaned));
                    }
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {}
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
    }
}

fn bp_cmd(
    port: &mut dyn serialport::SerialPort,
    cmd: &str,
    expect: &[&str],
    timeout: Duration,
) -> io::Result<String> {
    port.write_all(cmd.as_bytes())?;
    port.write_all(b"\r\n")?;
    port.flush()?;
    std::thread::sleep(Duration::from_millis(50));
    let (_, text) = port_read_until(port, expect, timeout)?;
    Ok(text)
}

#[allow(dead_code)]
fn bp_cmd_wait(
    port: &mut dyn serialport::SerialPort,
    cmd: &str,
    timeout: Duration,
) -> io::Result<String> {
    port.write_all(cmd.as_bytes())?;
    port.write_all(b"\r\n")?;
    port.flush()?;
    std::thread::sleep(Duration::from_millis(200));
    let mut raw = Vec::new();
    let mut buf = [0u8; 256];
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match port.read(&mut buf) {
            Ok(n) if n > 0 => raw.extend_from_slice(&buf[..n]),
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                if !raw.is_empty() {
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if !raw.is_empty() {
                    break;
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(strip_ansi(&raw))
}

// ── BP5 detection ───────────────────────────────────────────────────────

pub struct BpInfo {
    pub model: String,
    pub firmware: String,
    #[allow(dead_code)]
    pub raw_banner: String,
}

fn bp_detect(port: &mut dyn serialport::SerialPort) -> io::Result<BpInfo> {
    port_drain(port, 200);
    port.write_all(b"\r\n")?;
    port.flush()?;
    std::thread::sleep(Duration::from_millis(200));
    port_drain(port, 100);

    let text = bp_cmd(port, "i", &[">", "HiZ>", "UART>", "SPI>", "I2C>"], Duration::from_secs(3))?;

    let lower = text.to_ascii_lowercase();
    if !lower.contains("bus pirate") {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("not a Bus Pirate (got: {})", &text[..text.len().min(80)]),
        ));
    }

    let model = if lower.contains("bus pirate 5") || lower.contains("bp5") {
        "Bus Pirate 5".to_string()
    } else if lower.contains("bus pirate v3") || lower.contains("bp v3") {
        "Bus Pirate v3".to_string()
    } else if lower.contains("bus pirate v4") {
        "Bus Pirate v4".to_string()
    } else {
        "Bus Pirate (unknown version)".to_string()
    };

    let firmware = text
        .lines()
        .find(|l| {
            let ll = l.to_ascii_lowercase();
            ll.contains("firmware") || ll.contains("fw:") || ll.contains("version")
        })
        .unwrap_or("")
        .trim()
        .to_string();

    Ok(BpInfo {
        model,
        firmware,
        raw_banner: text,
    })
}

// ── BP5 configuration ───────────────────────────────────────────────────

fn bp_reset_hiz(port: &mut dyn serialport::SerialPort) -> io::Result<()> {
    port_drain(port, 100);
    bp_cmd(port, "#", &["HiZ>", "hiz>", ">"], Duration::from_secs(3))?;
    Ok(())
}

fn bp_configure_uart(
    port: &mut dyn serialport::SerialPort,
    target_baud: u32,
) -> io::Result<()> {
    bp_cmd(port, "m 3", &["speed", "baud", "UART>"], Duration::from_secs(3))?;

    let baud_str = target_baud.to_string();
    let resp = bp_cmd(
        port,
        &baud_str,
        &["data", "parity", "UART>", ">"],
        Duration::from_secs(2),
    )?;

    let lower = resp.to_ascii_lowercase();
    if lower.contains("data") {
        bp_cmd(port, "8", &["parity", "stop", "UART>", ">"], Duration::from_secs(2))?;
    }

    let lower2 = strip_ansi(&[]).to_ascii_lowercase();
    let _ = lower2;
    bp_cmd(port, "1", &["stop", "UART>", ">"], Duration::from_secs(2)).ok();
    bp_cmd(port, "1", &["UART>", ">"], Duration::from_secs(2)).ok();

    ui::detail(&format!("BP5 UART configured: {} 8N1", target_baud));
    Ok(())
}

fn bp_power_on(
    port: &mut dyn serialport::SerialPort,
    voltage: f32,
) -> io::Result<()> {
    if (voltage - 3.3).abs() > 0.01 {
        let cmd = format!("W {:.1}", voltage);
        bp_cmd(port, &cmd, &["UART>", ">", "power"], Duration::from_secs(2))?;
    } else {
        bp_cmd(port, "W", &["UART>", ">", "power", "on"], Duration::from_secs(2))?;
    }
    ui::detail(&format!("BP5 power supply ON ({:.1}V)", voltage));
    std::thread::sleep(Duration::from_millis(200));
    Ok(())
}

#[allow(dead_code)]
fn bp_power_off(port: &mut dyn serialport::SerialPort) -> io::Result<()> {
    bp_cmd(port, "w", &["UART>", ">", "off"], Duration::from_secs(2))?;
    ui::detail("BP5 power supply OFF");
    Ok(())
}

fn bp_pullups_on(port: &mut dyn serialport::SerialPort) -> io::Result<()> {
    bp_cmd(port, "P", &["UART>", ">", "pull"], Duration::from_secs(2))?;
    ui::detail("BP5 pull-ups enabled");
    Ok(())
}

fn bp_read_voltage(port: &mut dyn serialport::SerialPort) -> io::Result<String> {
    let text = bp_cmd(port, "v", &["UART>", ">", "V"], Duration::from_secs(3))?;
    Ok(text)
}

fn bp_pulse_aux(port: &mut dyn serialport::SerialPort) -> io::Result<()> {
    bp_cmd(port, "A", &["UART>", ">", "high", "1"], Duration::from_secs(1))?;
    std::thread::sleep(Duration::from_millis(100));
    bp_cmd(port, "a", &["UART>", ">", "low", "0"], Duration::from_secs(1))?;
    std::thread::sleep(Duration::from_millis(100));
    bp_cmd(port, "A", &["UART>", ">", "high", "1"], Duration::from_secs(1))?;
    ui::detail("BP5 AUX pin pulsed (high-low-high reset)");
    Ok(())
}

fn bp_enter_bridge(port: &mut dyn serialport::SerialPort) -> io::Result<()> {
    port.write_all(b"bridge\r\n")?;
    port.flush()?;
    std::thread::sleep(Duration::from_millis(300));
    port_drain(port, 200);
    ui::detail("BP5 UART bridge mode active");
    Ok(())
}

// ── baud scanning through BP5 ───────────────────────────────────────────

const SCAN_BAUDS: &[u32] = &[
    115200, 9600, 57600, 38400, 19200, 230400, 460800, 921600,
    1200, 2400, 4800, 14400, 28800, 76800,
];

fn bp_scan_baud(
    port: &mut dyn serialport::SerialPort,
    running: &AtomicBool,
) -> io::Result<Option<u32>> {
    ui::step("BP-SCAN", "scanning baud rates through BP5 bridge");
    let mut best_baud: Option<u32> = None;
    let mut best_score: usize = 0;

    for &candidate in SCAN_BAUDS {
        if !running.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted"));
        }
        bp_reset_hiz(port)?;
        bp_configure_uart(port, candidate)?;
        bp_enter_bridge(port)?;

        let mut sample = Vec::new();
        let mut buf = [0u8; 256];
        let deadline = Instant::now() + Duration::from_millis(800);
        while Instant::now() < deadline {
            match port.read(&mut buf) {
                Ok(n) if n > 0 => sample.extend_from_slice(&buf[..n]),
                _ => {}
            }
        }

        if !sample.is_empty() {
            let printable = sample
                .iter()
                .filter(|&&b| (0x20..=0x7e).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t')
                .count();
            let score = (printable * 100) / sample.len();
            ui::detail(&format!(
                "{}: {} bytes, {}% printable",
                candidate, sample.len(), score
            ));
            if score > best_score && score >= 60 {
                best_score = score;
                best_baud = Some(candidate);
            }
        }

        port_drain(port, 50);
    }
    Ok(best_baud)
}

// ── public API ──────────────────────────────────────────────────────────

pub struct BpOptions {
    pub power: bool,
    pub voltage: f32,
    pub pullups: bool,
    pub aux_reset: bool,
    pub info_only: bool,
    pub scan: bool,
}

impl Default for BpOptions {
    fn default() -> Self {
        Self {
            power: false,
            voltage: 3.3,
            pullups: false,
            aux_reset: false,
            info_only: false,
            scan: false,
        }
    }
}

pub fn bp_flow(
    port_path: &str,
    target_baud: u32,
    opts: &BpOptions,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    println!(
        "\n{}",
        "=== BUS PIRATE 5 ===".bold().magenta()
    );
    println!("{} {}", "Port:".cyan(), port_path);

    let mut port = serialport::new(port_path, 115200)
        .timeout(Duration::from_millis(200))
        .open()
        .map_err(|e| format!("open {}: {}", port_path, e))?;

    let info = bp_detect(&mut *port).map_err(|e| -> Box<dyn Error> {
        format!("BP5 detection failed: {} (is this a Bus Pirate?)", e).into()
    })?;

    ui::found(&format!("{}", info.model));
    if !info.firmware.is_empty() {
        ui::detail(&info.firmware);
    }

    if !info.model.contains("5") && !info.model.contains("unknown") {
        ui::warn("only Bus Pirate 5 is fully supported; v3/v4 may work but are untested");
    }

    bp_reset_hiz(&mut *port)?;

    if opts.info_only {
        let voltages = bp_read_voltage(&mut *port)?;
        println!("\n{}", "Pin voltages:".bold().cyan());
        for line in voltages.lines() {
            let l = line.trim();
            if l.contains('V') || l.contains('v') {
                println!("  {}", l);
            }
        }
        return Ok(());
    }

    if opts.scan {
        let found = bp_scan_baud(&mut *port, &running)?;
        match found {
            Some(b) => {
                ui::win("BP5 BAUD DETECTED", &format!("{} baud", b));
                bp_reset_hiz(&mut *port)?;
                bp_configure_uart(&mut *port, b)?;
            }
            None => {
                ui::fail("no readable baud rate found through BP5 bridge");
                return Ok(());
            }
        }
    } else {
        bp_configure_uart(&mut *port, target_baud)?;
    }

    if opts.power {
        bp_power_on(&mut *port, opts.voltage)?;
    }

    if opts.pullups {
        bp_pullups_on(&mut *port)?;
    }

    let voltages = bp_read_voltage(&mut *port)?;
    for line in voltages.lines() {
        let l = line.trim();
        if l.contains('V') && (l.contains("IO") || l.contains("Vout") || l.contains("vout")) {
            ui::detail(l);
        }
    }

    if opts.aux_reset {
        bp_pulse_aux(&mut *port)?;
        std::thread::sleep(Duration::from_millis(500));
    }

    bp_enter_bridge(&mut *port)?;

    ui::win("BP5 READY", &format!(
        "UART bridge at {} baud - target connected through BP5",
        if opts.scan { "detected".to_string() } else { target_baud.to_string() }
    ));

    drop(port);

    Ok(())
}

// ── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ansi_strip_removes_sgr() {
        let raw = b"\x1b[31mERROR\x1b[0m: something";
        assert_eq!(strip_ansi(raw), "ERROR: something");
    }

    #[test]
    fn ansi_strip_removes_cursor() {
        let raw = b"\x1b[2J\x1b[HBus Pirate 5";
        assert_eq!(strip_ansi(raw), "Bus Pirate 5");
    }

    #[test]
    fn ansi_strip_passthrough_clean() {
        let raw = b"UART> bridge\r\n";
        assert_eq!(strip_ansi(raw), "UART> bridge\r\n");
    }

    #[test]
    fn ansi_strip_removes_control_chars() {
        let raw = b"hello\x07\x08world";
        assert_eq!(strip_ansi(raw), "helloworld");
    }

    #[test]
    fn ansi_strip_complex_sequences() {
        let raw = b"\x1b[1;32mOK\x1b[0m \x1b[33;1mWARN\x1b[0m done";
        assert_eq!(strip_ansi(raw), "OK WARN done");
    }

    #[test]
    fn ansi_strip_bare_esc() {
        let raw = b"\x1bXfoo";
        assert_eq!(strip_ansi(raw), "foo");
    }

    #[test]
    fn ansi_strip_empty() {
        assert_eq!(strip_ansi(b""), "");
    }
}
