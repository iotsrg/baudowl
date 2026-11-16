use std::error::Error;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use colored::*;

use crate::ui;

// ── constants ───────────────────────────────────────────────────────────

const BP5_CDC_BAUD: u32 = 115200;
const CMD_TIMEOUT: Duration = Duration::from_secs(2);
const DETECT_TIMEOUT: Duration = Duration::from_secs(3);

const VALID_VOLTAGES: &[f32] = &[1.8, 2.5, 3.3, 5.0];

const SCAN_BAUDS: &[u32] = &[
    115200, 9600, 57600, 38400, 19200, 230400, 460800, 921600,
    1200, 2400, 4800, 14400, 28800, 76800,
];

const BAUD_SCAN_WINDOW_MS: u64 = 800;
const BAUD_SCAN_THRESHOLD: usize = 60;
const BAUD_SCAN_EARLY_EXIT: usize = 90;

// ── ANSI escape stripping ───────────────────────────────────────────────

fn strip_ansi(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == 0x1b {
            i += 1;
            if i < raw.len() && raw[i] == b'[' {
                // CSI sequence: ESC [ ... final_byte(0x40-0x7E)
                i += 1;
                while i < raw.len() && !(0x40..=0x7e).contains(&raw[i]) {
                    i += 1;
                }
                if i < raw.len() {
                    i += 1;
                }
            } else if i < raw.len() {
                // Non-CSI escape: skip one byte after ESC
                i += 1;
            }
        } else if raw[i] >= 0x20 || raw[i] == b'\n' || raw[i] == b'\r' || raw[i] == b'\t' {
            out.push(raw[i]);
            i += 1;
        } else {
            // Strip other control chars (BEL, BS, etc.)
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
            let tail = if cleaned.len() > 120 {
                &cleaned[cleaned.len() - 120..]
            } else {
                &cleaned
            };
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("BP5: timeout waiting for {:?} (got: {})", patterns, tail),
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

// ── BP5 detection ───────────────────────────────────────────────────────

pub struct BpInfo {
    pub model: String,
    pub firmware: String,
    pub raw_banner: String,
}

fn bp_detect(port: &mut dyn serialport::SerialPort) -> io::Result<BpInfo> {
    port_drain(port, 200);
    port.write_all(b"\r\n")?;
    port.flush()?;
    std::thread::sleep(Duration::from_millis(200));
    port_drain(port, 100);

    let text = bp_cmd(
        port,
        "i",
        &[">", "HiZ>", "UART>", "SPI>", "I2C>"],
        DETECT_TIMEOUT,
    )?;

    let lower = text.to_ascii_lowercase();
    if !lower.contains("bus pirate") {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("not a Bus Pirate (got: {})", &text[..text.len().min(80)]),
        ));
    }

    let model = parse_model(&lower);

    let firmware = text
        .lines()
        .find(|l| {
            let ll = l.to_ascii_lowercase();
            ll.contains("firmware") || ll.contains("fw:") || ll.contains("version")
        })
        .unwrap_or("")
        .trim()
        .to_string();

    Ok(BpInfo { model, firmware, raw_banner: text })
}

fn parse_model(lower: &str) -> String {
    if lower.contains("bus pirate 5") || lower.contains("bp5") {
        "Bus Pirate 5".to_string()
    } else if lower.contains("bus pirate v3") || lower.contains("bp v3") {
        "Bus Pirate v3".to_string()
    } else if lower.contains("bus pirate v4") {
        "Bus Pirate v4".to_string()
    } else {
        "Bus Pirate (unknown version)".to_string()
    }
}

// ── voltage validation ──────────────────────────────────────────────────

fn validate_voltage(v: f32) -> Result<(), String> {
    for &valid in VALID_VOLTAGES {
        if (v - valid).abs() < 0.01 {
            return Ok(());
        }
    }
    Err(format!(
        "invalid voltage {:.1}V (valid: {})",
        v,
        VALID_VOLTAGES
            .iter()
            .map(|v| format!("{:.1}", v))
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

// ── BP5 configuration ───────────────────────────────────────────────────

fn bp_reset_hiz(port: &mut dyn serialport::SerialPort) -> io::Result<()> {
    port_drain(port, 100);
    bp_cmd(port, "#", &["HiZ>", "hiz>", ">"], DETECT_TIMEOUT)?;
    Ok(())
}

fn bp_configure_uart(
    port: &mut dyn serialport::SerialPort,
    target_baud: u32,
) -> io::Result<()> {
    bp_cmd(port, "m 3", &["speed", "baud", "UART>"], DETECT_TIMEOUT)?;

    let baud_str = target_baud.to_string();
    let resp = bp_cmd(
        port,
        &baud_str,
        &["data", "parity", "UART>", ">"],
        CMD_TIMEOUT,
    )?;

    let lower = resp.to_ascii_lowercase();
    if lower.contains("data") {
        bp_cmd(port, "8", &["parity", "stop", "UART>", ">"], CMD_TIMEOUT)?;
    }

    if let Err(e) = bp_cmd(port, "1", &["stop", "UART>", ">"], CMD_TIMEOUT) {
        ui::warn(&format!("BP5 parity config: {}", e));
    }
    if let Err(e) = bp_cmd(port, "1", &["UART>", ">"], CMD_TIMEOUT) {
        ui::warn(&format!("BP5 stop-bit config: {}", e));
    }

    ui::detail(&format!("BP5 UART configured: {} 8N1", target_baud));
    Ok(())
}

fn bp_power_on(
    port: &mut dyn serialport::SerialPort,
    voltage: f32,
) -> io::Result<()> {
    if (voltage - 3.3).abs() > 0.01 {
        let cmd = format!("W {:.1}", voltage);
        bp_cmd(port, &cmd, &["UART>", ">", "power"], CMD_TIMEOUT)?;
    } else {
        bp_cmd(port, "W", &["UART>", ">", "power", "on"], CMD_TIMEOUT)?;
    }
    ui::detail(&format!("BP5 power supply ON ({:.1}V)", voltage));
    std::thread::sleep(Duration::from_millis(200));
    Ok(())
}

pub fn bp_power_off(port: &mut dyn serialport::SerialPort) -> io::Result<()> {
    bp_cmd(port, "w", &["UART>", ">", "off"], CMD_TIMEOUT)?;
    ui::detail("BP5 power supply OFF");
    Ok(())
}

fn bp_pullups_on(port: &mut dyn serialport::SerialPort) -> io::Result<()> {
    bp_cmd(port, "P", &["UART>", ">", "pull"], CMD_TIMEOUT)?;
    ui::detail("BP5 pull-ups enabled");
    Ok(())
}

fn bp_read_voltage(port: &mut dyn serialport::SerialPort) -> io::Result<String> {
    let text = bp_cmd(port, "v", &["UART>", ">", "V"], DETECT_TIMEOUT)?;
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
        let deadline = Instant::now() + Duration::from_millis(BAUD_SCAN_WINDOW_MS);
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
                candidate,
                sample.len(),
                score
            ));
            if score > best_score && score >= BAUD_SCAN_THRESHOLD {
                best_score = score;
                best_baud = Some(candidate);
            }
            if score >= BAUD_SCAN_EARLY_EXIT {
                ui::detail("high confidence, skipping remaining rates");
                break;
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
}

impl Default for BpOptions {
    fn default() -> Self {
        Self {
            power: false,
            voltage: 3.3,
            pullups: false,
            aux_reset: false,
        }
    }
}

pub fn bp_info(port_path: &str) -> Result<(), Box<dyn Error>> {
    ui::section("=== BUS PIRATE 5 (info) ===");
    println!("{} {}", "Port:".cyan(), port_path);

    let mut port = serialport::new(port_path, BP5_CDC_BAUD)
        .timeout(Duration::from_millis(200))
        .open()
        .map_err(|e| format!("open {}: {}", port_path, e))?;

    let info = bp_detect(&mut *port).map_err(|e| -> Box<dyn Error> {
        format!("BP5 detection failed: {} (is this a Bus Pirate?)", e).into()
    })?;

    ui::found(&info.model);
    if !info.firmware.is_empty() {
        ui::detail(&info.firmware);
    }
    println!("\n{}", "Banner:".bold().cyan());
    for line in info.raw_banner.lines() {
        let l = line.trim();
        if !l.is_empty() {
            println!("  {}", l);
        }
    }

    bp_reset_hiz(&mut *port)?;
    let voltages = bp_read_voltage(&mut *port)?;
    println!("\n{}", "Pin voltages:".bold().cyan());
    for line in voltages.lines() {
        let l = line.trim();
        if l.contains('V') || l.contains('v') {
            println!("  {}", l);
        }
    }
    Ok(())
}

pub fn bp_scan(
    port_path: &str,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    ui::section("=== BUS PIRATE 5 (baud scan) ===");
    println!("{} {}", "Port:".cyan(), port_path);

    let mut port = serialport::new(port_path, BP5_CDC_BAUD)
        .timeout(Duration::from_millis(200))
        .open()
        .map_err(|e| format!("open {}: {}", port_path, e))?;

    let info = bp_detect(&mut *port)?;
    ui::found(&info.model);
    bp_reset_hiz(&mut *port)?;

    let found = bp_scan_baud(&mut *port, &running)?;
    match found {
        Some(b) => ui::win("BP5 BAUD DETECTED", &format!("{} baud", b)),
        None => ui::fail("no readable baud rate found through BP5 bridge"),
    }
    Ok(())
}

pub fn bp_setup(
    port_path: &str,
    target_baud: u32,
    opts: &BpOptions,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    ui::section("=== BUS PIRATE 5 ===");
    println!("{} {}", "Port:".cyan(), port_path);

    if opts.power {
        validate_voltage(opts.voltage)
            .map_err(|e| -> Box<dyn Error> { e.into() })?;
    }

    let mut port = serialport::new(port_path, BP5_CDC_BAUD)
        .timeout(Duration::from_millis(200))
        .open()
        .map_err(|e| format!("open {}: {}", port_path, e))?;

    let info = bp_detect(&mut *port).map_err(|e| -> Box<dyn Error> {
        format!("BP5 detection failed: {} (is this a Bus Pirate?)", e).into()
    })?;

    ui::found(&info.model);
    if !info.firmware.is_empty() {
        ui::detail(&info.firmware);
    }

    if !info.model.contains("5") && !info.model.contains("unknown") {
        ui::warn("only Bus Pirate 5 is fully supported; v3/v4 may work but are untested");
    }

    bp_reset_hiz(&mut *port)?;

    let configure_result = (|| -> Result<(), Box<dyn Error>> {
        bp_configure_uart(&mut *port, target_baud)?;

        if opts.power {
            bp_power_on(&mut *port, opts.voltage)?;
        }

        if opts.pullups {
            bp_pullups_on(&mut *port)?;
        }

        let voltages = bp_read_voltage(&mut *port)?;
        for line in voltages.lines() {
            let l = line.trim();
            if l.contains('V')
                && (l.contains("IO") || l.contains("Vout") || l.contains("vout"))
            {
                ui::detail(l);
            }
        }

        if opts.aux_reset {
            bp_pulse_aux(&mut *port)?;
            std::thread::sleep(Duration::from_millis(500));
        }

        if !running.load(Ordering::SeqCst) {
            return Err("interrupted".into());
        }

        bp_enter_bridge(&mut *port)?;
        Ok(())
    })();

    if let Err(ref e) = configure_result {
        if opts.power {
            let _ = bp_power_off(&mut *port);
        }
        return Err(format!("BP5 setup failed: {}", e).into());
    }

    ui::win(
        "BP5 READY",
        &format!("UART bridge at {} baud", target_baud),
    );
    Ok(())
}

// ── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- ANSI stripping --

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

    // -- model detection --

    #[test]
    fn parse_model_bp5_variants() {
        assert_eq!(parse_model("bus pirate 5 rev10"), "Bus Pirate 5");
        assert_eq!(parse_model("bp5 firmware 2.0"), "Bus Pirate 5");
    }

    #[test]
    fn parse_model_bp3_bp4() {
        assert_eq!(parse_model("bus pirate v3.6"), "Bus Pirate v3");
        assert_eq!(parse_model("bp v3 community"), "Bus Pirate v3");
        assert_eq!(parse_model("bus pirate v4.0"), "Bus Pirate v4");
    }

    #[test]
    fn parse_model_unknown() {
        assert_eq!(
            parse_model("bus pirate something"),
            "Bus Pirate (unknown version)"
        );
    }

    // -- voltage validation --

    #[test]
    fn valid_voltages_accepted() {
        assert!(validate_voltage(1.8).is_ok());
        assert!(validate_voltage(2.5).is_ok());
        assert!(validate_voltage(3.3).is_ok());
        assert!(validate_voltage(5.0).is_ok());
    }

    #[test]
    fn invalid_voltages_rejected() {
        assert!(validate_voltage(0.0).is_err());
        assert!(validate_voltage(2.0).is_err());
        assert!(validate_voltage(4.0).is_err());
        assert!(validate_voltage(12.0).is_err());
    }

    // -- scan bauds --

    #[test]
    fn scan_bauds_starts_with_common_rates() {
        assert_eq!(SCAN_BAUDS[0], 115200);
        assert_eq!(SCAN_BAUDS[1], 9600);
        assert!(SCAN_BAUDS.contains(&57600));
        assert!(SCAN_BAUDS.contains(&921600));
    }

    #[test]
    fn scan_thresholds_are_sane() {
        assert!(BAUD_SCAN_THRESHOLD < BAUD_SCAN_EARLY_EXIT);
        assert!(BAUD_SCAN_EARLY_EXIT <= 100);
    }
}
