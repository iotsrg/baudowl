// Debugging utilities: hexdump, timestamped logging, UART fingerprint,
// protocol decode, and trigger-capture.

use std::error::Error;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use colored::*;

use crate::ui;

// ── hexdump ─────────────────────────────────────────────────────────────

pub fn hexdump(
    port_path: &str,
    baud: u32,
    max_bytes: usize,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    ui::section("=== HEXDUMP ===");
    println!("{} {} @ {} baud (Ctrl-C to stop)", "Port:".cyan(), port_path, baud);

    let mut port = serialport::new(port_path, baud)
        .timeout(Duration::from_millis(200))
        .open()
        .map_err(|e| format!("open {}: {}", port_path, e))?;

    port.clear(serialport::ClearBuffer::All).ok();
    let mut buf = [0u8; 16];
    let mut offset: usize = 0;

    while running.load(Ordering::SeqCst) && offset < max_bytes {
        let n = match port.read(&mut buf) {
            Ok(n) if n > 0 => n,
            _ => continue,
        };

        // Print offset
        print!("{:08x}  ", offset);

        // Hex bytes
        for i in 0..16 {
            if i < n {
                print!("{:02x} ", buf[i]);
            } else {
                print!("   ");
            }
            if i == 7 { print!(" "); }
        }

        // ASCII
        print!(" |");
        for i in 0..n {
            let c = buf[i];
            if (0x20..=0x7e).contains(&c) {
                print!("{}", c as char);
            } else {
                print!(".");
            }
        }
        println!("|");

        offset += n;
    }

    println!("\n{} bytes dumped", offset);
    Ok(())
}

// ── timestamped log ─────────────────────────────────────────────────────

pub fn log_session(
    port_path: &str,
    baud: u32,
    out_path: &str,
    raw: bool,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    ui::section("=== SESSION LOG ===");
    println!("{} {} @ {} baud -> {}", "Port:".cyan(), port_path, baud, out_path);

    let mut port = serialport::new(port_path, baud)
        .timeout(Duration::from_millis(200))
        .open()
        .map_err(|e| format!("open {}: {}", port_path, e))?;

    port.clear(serialport::ClearBuffer::All).ok();

    let mut file = std::fs::File::create(out_path)?;
    let start = Instant::now();
    let mut total: usize = 0;
    let mut buf = [0u8; 256];
    let mut line_buf = Vec::new();

    writeln!(file, "# baudowl session log")?;
    writeln!(file, "# port: {} baud: {}", port_path, baud)?;
    writeln!(file, "# started: {:?}", std::time::SystemTime::now())?;
    writeln!(file, "#")?;
    writeln!(file, "# format: [timestamp_us] data")?;
    writeln!(file, "")?;

    while running.load(Ordering::SeqCst) {
        let n = match port.read(&mut buf) {
            Ok(n) if n > 0 => n,
            _ => continue,
        };

        let ts = start.elapsed().as_micros();
        total += n;

        if raw {
            // Raw hex log
            write!(file, "[{:012}] ", ts)?;
            for &b in &buf[..n] {
                write!(file, "{:02x} ", b)?;
            }
            writeln!(file)?;
        } else {
            // Line-buffered text log
            for &b in &buf[..n] {
                if b == b'\n' {
                    let text = String::from_utf8_lossy(&line_buf);
                    writeln!(file, "[{:012}] {}", ts, text.trim_end())?;
                    // Also print to stdout
                    println!(
                        "{} {}",
                        format!("[{:>10}us]", ts).dimmed(),
                        text.trim_end()
                    );
                    line_buf.clear();
                } else if b != b'\r' {
                    line_buf.push(b);
                }
            }
        }
    }

    // Flush remaining
    if !line_buf.is_empty() {
        let ts = start.elapsed().as_micros();
        let text = String::from_utf8_lossy(&line_buf);
        writeln!(file, "[{:012}] {}", ts, text.trim_end())?;
    }

    file.flush()?;
    ui::win("SESSION LOG", &format!("{} bytes logged to {}", total, out_path));
    Ok(())
}

// ── UART fingerprint ────────────────────────────────────────────────────

struct Fingerprint {
    name: &'static str,
    patterns: &'static [&'static str],
}

const FINGERPRINTS: &[Fingerprint] = &[
    Fingerprint { name: "U-Boot", patterns: &["U-Boot", "u-boot", "Hit any key to stop autoboot"] },
    Fingerprint { name: "Barebox", patterns: &["barebox", "Barebox"] },
    Fingerprint { name: "RedBoot", patterns: &["RedBoot", "redboot"] },
    Fingerprint { name: "CFE", patterns: &["CFE>", "Broadcom CFE", "CFE version"] },
    Fingerprint { name: "GRUB", patterns: &["GNU GRUB", "grub>"] },
    Fingerprint { name: "OpenWrt", patterns: &["OpenWrt", "openwrt", "LEDE"] },
    Fingerprint { name: "BusyBox", patterns: &["BusyBox", "busybox"] },
    Fingerprint { name: "Linux kernel", patterns: &["Linux version", "Booting Linux", "Kernel command line"] },
    Fingerprint { name: "Android", patterns: &["AndroidBoot", "android", "fastboot"] },
    Fingerprint { name: "VxWorks", patterns: &["VxWorks", "vxWorks", "Wind River"] },
    Fingerprint { name: "eCos", patterns: &["eCos", "RedBoot"] },
    Fingerprint { name: "FreeRTOS", patterns: &["FreeRTOS", "freertos"] },
    Fingerprint { name: "Zephyr", patterns: &["zephyr", "Zephyr", "*** Booting Zephyr"] },
    Fingerprint { name: "ThreadX", patterns: &["ThreadX", "Azure RTOS"] },
    Fingerprint { name: "MicroPython", patterns: &["MicroPython", "micropython", ">>> "] },
    Fingerprint { name: "CircuitPython", patterns: &["CircuitPython", "Adafruit CircuitPython"] },
    Fingerprint { name: "Arduino", patterns: &["Arduino", "arduino"] },
    Fingerprint { name: "ESP-IDF", patterns: &["ESP-IDF", "esp-idf", "I ("] },
    Fingerprint { name: "NuttX", patterns: &["NuttX", "nuttx", "NuttShell"] },
    Fingerprint { name: "RIOT OS", patterns: &["RIOT", "riot"] },
    Fingerprint { name: "AT command", patterns: &["OK\r\n", "+CME ERROR", "AT+"] },
    Fingerprint { name: "Cisco IOS", patterns: &["Cisco IOS", "cisco", "Router>", "Switch>"] },
    Fingerprint { name: "MikroTik", patterns: &["MikroTik", "RouterOS"] },
    Fingerprint { name: "Telnet banner", patterns: &["login:", "Login:", "Username:"] },
];

pub fn fingerprint(
    port_path: &str,
    baud: u32,
    sample_secs: u64,
    running: Arc<AtomicBool>,
) -> Result<Vec<String>, Box<dyn Error>> {
    ui::section("=== UART FINGERPRINT ===");
    println!("{} {} @ {} baud, sampling {}s", "Port:".cyan(), port_path, baud, sample_secs);

    let mut port = serialport::new(port_path, baud)
        .timeout(Duration::from_millis(200))
        .open()
        .map_err(|e| format!("open {}: {}", port_path, e))?;

    port.clear(serialport::ClearBuffer::All).ok();

    // Collect data for the sample period
    let mut data = Vec::new();
    let mut buf = [0u8; 256];
    let deadline = Instant::now() + Duration::from_secs(sample_secs);

    while Instant::now() < deadline && running.load(Ordering::SeqCst) && data.len() < 32768 {
        if let Ok(n) = port.read(&mut buf) {
            data.extend_from_slice(&buf[..n]);
        }
    }

    if data.is_empty() {
        ui::warn("no data received (is the target sending? try resetting it)");
        return Ok(Vec::new());
    }

    let text = String::from_utf8_lossy(&data);
    ui::detail(&format!("captured {} bytes", data.len()));

    // Check all fingerprints
    let mut matches = Vec::new();
    for fp in FINGERPRINTS {
        for &pat in fp.patterns {
            if text.contains(pat) {
                matches.push(fp.name.to_string());
                ui::found(&format!("{} (matched: \"{}\")", fp.name, pat));
                break;
            }
        }
    }

    if matches.is_empty() {
        ui::warn("no known firmware/OS signatures found in captured data");
        // Show a preview of what we got
        let preview: String = text.chars().take(200).collect();
        ui::detail(&format!("preview: {}", preview));
    } else {
        ui::win("FINGERPRINT", &format!("{} signature(s) matched", matches.len()));
    }

    Ok(matches)
}

// ── bus decode ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum DecodedFrame {
    Ascii(String),
    ModbusRtu { addr: u8, func: u8, data_len: usize },
    Nmea(String),
    Slip { payload_len: usize },
    AtCommand(String),
    Unknown { len: usize, hex: String },
}

fn try_decode_modbus(data: &[u8]) -> Option<DecodedFrame> {
    if data.len() < 4 { return None; }
    let addr = data[0];
    let func = data[1];
    // Valid Modbus function codes: 1-6, 15, 16
    if !matches!(func, 1..=6 | 15 | 16) { return None; }
    Some(DecodedFrame::ModbusRtu { addr, func, data_len: data.len() - 4 })
}

fn try_decode_nmea(data: &[u8]) -> Option<DecodedFrame> {
    let s = std::str::from_utf8(data).ok()?;
    let trimmed = s.trim();
    if trimmed.starts_with('$') && trimmed.contains('*') {
        Some(DecodedFrame::Nmea(trimmed.to_string()))
    } else {
        None
    }
}

fn try_decode_at(data: &[u8]) -> Option<DecodedFrame> {
    let s = std::str::from_utf8(data).ok()?;
    let trimmed = s.trim();
    if trimmed.starts_with("AT") || trimmed == "OK" || trimmed.starts_with("+CME") || trimmed.starts_with("+CMS") {
        Some(DecodedFrame::AtCommand(trimmed.to_string()))
    } else {
        None
    }
}

fn try_decode_slip(data: &[u8]) -> Option<DecodedFrame> {
    if data.len() >= 2 && data[0] == 0xC0 && data[data.len() - 1] == 0xC0 {
        Some(DecodedFrame::Slip { payload_len: data.len() - 2 })
    } else {
        None
    }
}

fn decode_chunk(data: &[u8]) -> DecodedFrame {
    // Try protocol decoders in priority order
    if let Some(f) = try_decode_nmea(data) { return f; }
    if let Some(f) = try_decode_at(data) { return f; }
    if let Some(f) = try_decode_slip(data) { return f; }
    if let Some(f) = try_decode_modbus(data) { return f; }

    // Check if it's printable ASCII
    let printable = data.iter().filter(|&&b| (0x20..=0x7e).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r')).count();
    if printable * 100 / data.len().max(1) > 80 {
        let text = String::from_utf8_lossy(data).trim().to_string();
        return DecodedFrame::Ascii(text);
    }

    // Unknown binary
    let hex: String = data.iter().take(32).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
    DecodedFrame::Unknown { len: data.len(), hex }
}

fn format_decoded(frame: &DecodedFrame) -> String {
    match frame {
        DecodedFrame::Ascii(s) => format!("[ASCII] {}", s),
        DecodedFrame::ModbusRtu { addr, func, data_len } => {
            format!("[MODBUS] addr={} func={} data={}B", addr, func, data_len)
        }
        DecodedFrame::Nmea(s) => format!("[NMEA] {}", s),
        DecodedFrame::Slip { payload_len } => format!("[SLIP] {}B payload", payload_len),
        DecodedFrame::AtCommand(s) => format!("[AT] {}", s),
        DecodedFrame::Unknown { len, hex } => format!("[BIN:{}B] {}", len, hex),
    }
}

pub fn bus_decode(
    port_path: &str,
    baud: u32,
    idle_ms: u64,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    ui::section("=== BUS DECODE ===");
    println!("{} {} @ {} baud, idle gap {}ms", "Port:".cyan(), port_path, baud, idle_ms);

    let mut port = serialport::new(port_path, baud)
        .timeout(Duration::from_millis(idle_ms))
        .open()
        .map_err(|e| format!("open {}: {}", port_path, e))?;

    port.clear(serialport::ClearBuffer::All).ok();

    let mut frame_buf = Vec::new();
    let mut buf = [0u8; 256];
    let mut frame_count: u64 = 0;
    let mut last_rx = Instant::now();

    while running.load(Ordering::SeqCst) {
        match port.read(&mut buf) {
            Ok(n) if n > 0 => {
                frame_buf.extend_from_slice(&buf[..n]);
                last_rx = Instant::now();
            }
            _ => {
                // Idle timeout - decode whatever we have
                if !frame_buf.is_empty() && last_rx.elapsed() >= Duration::from_millis(idle_ms) {
                    frame_count += 1;
                    let decoded = decode_chunk(&frame_buf);
                    println!(
                        "{} #{:>4}  {}",
                        format!("[{:>10}us]", last_rx.elapsed().as_micros()).dimmed(),
                        frame_count,
                        format_decoded(&decoded),
                    );
                    frame_buf.clear();
                }
            }
        }
    }

    // Flush remaining
    if !frame_buf.is_empty() {
        frame_count += 1;
        let decoded = decode_chunk(&frame_buf);
        println!("#{:>4}  {}", frame_count, format_decoded(&decoded));
    }

    ui::win("BUS DECODE", &format!("{} frames decoded", frame_count));
    Ok(())
}

// ── trigger capture ─────────────────────────────────────────────────────

pub fn trigger_capture(
    port_path: &str,
    baud: u32,
    trigger: &[u8],
    capture_bytes: usize,
    out_path: &str,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    ui::section("=== TRIGGER CAPTURE ===");
    let trigger_hex: String = trigger.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
    println!("{} {} @ {} baud", "Port:".cyan(), port_path, baud);
    println!("{} trigger=[{}], capture {} bytes after trigger", "Config:".cyan(), trigger_hex, capture_bytes);

    let mut port = serialport::new(port_path, baud)
        .timeout(Duration::from_millis(200))
        .open()
        .map_err(|e| format!("open {}: {}", port_path, e))?;

    port.clear(serialport::ClearBuffer::All).ok();

    ui::step("TRIG", "waiting for trigger pattern...");

    // Ring buffer for trigger matching
    let mut ring = Vec::with_capacity(trigger.len());
    let mut buf = [0u8; 1];
    let mut triggered = false;

    while running.load(Ordering::SeqCst) && !triggered {
        if let Ok(1) = port.read(&mut buf) {
            ring.push(buf[0]);
            if ring.len() > trigger.len() {
                ring.remove(0);
            }
            if ring == trigger {
                triggered = true;
                ui::found("trigger pattern matched!");
            }
        }
    }

    if !triggered {
        ui::warn("interrupted before trigger");
        return Ok(());
    }

    // Capture post-trigger data
    ui::step("TRIG", &format!("capturing {} bytes...", capture_bytes));
    let mut data = Vec::with_capacity(capture_bytes);
    let mut big_buf = [0u8; 256];

    while data.len() < capture_bytes && running.load(Ordering::SeqCst) {
        if let Ok(n) = port.read(&mut big_buf) {
            let take = n.min(capture_bytes - data.len());
            data.extend_from_slice(&big_buf[..take]);
        }
    }

    std::fs::write(out_path, &data)?;
    ui::win("TRIGGER CAPTURE", &format!("{} bytes captured to {}", data.len(), out_path));

    Ok(())
}

// ── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_ascii() {
        let data = b"Hello, world!\r\n";
        match decode_chunk(data) {
            DecodedFrame::Ascii(s) => assert!(s.contains("Hello")),
            other => panic!("expected Ascii, got {:?}", other),
        }
    }

    #[test]
    fn decode_nmea() {
        let data = b"$GPGGA,123456.00,4807.038,N*47\r\n";
        match decode_chunk(data) {
            DecodedFrame::Nmea(s) => assert!(s.starts_with("$GP")),
            other => panic!("expected Nmea, got {:?}", other),
        }
    }

    #[test]
    fn decode_at_command() {
        let data = b"AT+CGMI\r\n";
        match decode_chunk(data) {
            DecodedFrame::AtCommand(s) => assert_eq!(s, "AT+CGMI"),
            other => panic!("expected AtCommand, got {:?}", other),
        }
    }

    #[test]
    fn decode_slip_frame() {
        let data = &[0xC0, 0x01, 0x02, 0x03, 0xC0];
        match decode_chunk(data) {
            DecodedFrame::Slip { payload_len } => assert_eq!(payload_len, 3),
            other => panic!("expected Slip, got {:?}", other),
        }
    }

    #[test]
    fn decode_binary_unknown() {
        let data = &[0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90, 0xA0, 0xB0];
        match decode_chunk(data) {
            DecodedFrame::Unknown { len, .. } => assert_eq!(len, 8),
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn fingerprint_patterns_nonempty() {
        assert!(!FINGERPRINTS.is_empty());
        for fp in FINGERPRINTS {
            assert!(!fp.patterns.is_empty());
            assert!(!fp.name.is_empty());
        }
    }

    #[test]
    fn format_decoded_covers_all_variants() {
        let cases = vec![
            DecodedFrame::Ascii("test".into()),
            DecodedFrame::ModbusRtu { addr: 1, func: 3, data_len: 4 },
            DecodedFrame::Nmea("$GPGGA".into()),
            DecodedFrame::Slip { payload_len: 10 },
            DecodedFrame::AtCommand("AT+OK".into()),
            DecodedFrame::Unknown { len: 5, hex: "ff fe".into() },
        ];
        for c in cases {
            let s = format_decoded(&c);
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn modbus_rejects_invalid_function() {
        // Function code 0 is invalid
        let data = &[0x01, 0x00, 0x00, 0x00, 0x00];
        assert!(try_decode_modbus(data).is_none());
        // Function code 3 (read holding registers) is valid
        let data = &[0x01, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB];
        assert!(try_decode_modbus(data).is_some());
    }
}
