// I2C bus scanning and EEPROM dumping through Bus Pirate 5.
//
// BP5 text mode: `m 6` selects I2C, then `(1)` for speed.
// `[0xA0` starts a write to EEPROM address 0x50 (shifted left).
// Scan: iterate 7-bit addresses, check for ACK.

use std::error::Error;
use std::io::{self};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use colored::*;

use crate::ui;

const BP5_BAUD: u32 = 115200;
const CMD_TIMEOUT: Duration = Duration::from_secs(2);
const I2C_ADDR_MIN: u8 = 0x03;
const I2C_ADDR_MAX: u8 = 0x77;

fn bp_send(port: &mut dyn serialport::SerialPort, cmd: &str) -> io::Result<String> {
    port.write_all(cmd.as_bytes())?;
    port.write_all(b"\r\n")?;
    port.flush()?;
    std::thread::sleep(Duration::from_millis(200));
    let mut buf = [0u8; 4096];
    let mut out = Vec::new();
    let deadline = std::time::Instant::now() + CMD_TIMEOUT;
    while std::time::Instant::now() < deadline {
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

pub fn i2c_scan(
    port_path: &str,
    running: Arc<AtomicBool>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    ui::section("=== I2C SCAN (Bus Pirate 5) ===");
    println!("{} {}", "Port:".cyan(), port_path);

    let mut port = serialport::new(port_path, BP5_BAUD)
        .timeout(Duration::from_millis(500))
        .open()
        .map_err(|e| format!("open {}: {}", port_path, e))?;

    // Reset to HiZ, then select I2C mode
    ui::step("I2C", "configuring BP5 for I2C");
    bp_send(&mut *port, "#")?;
    std::thread::sleep(Duration::from_millis(500));
    bp_send(&mut *port, "m 6")?;
    std::thread::sleep(Duration::from_millis(300));
    // Select speed: (1) = ~100kHz standard
    bp_send(&mut *port, "1")?;
    std::thread::sleep(Duration::from_millis(200));

    ui::step("I2C", &format!("scanning addresses {:#04x}-{:#04x}", I2C_ADDR_MIN, I2C_ADDR_MAX));
    let mut found = Vec::new();

    for addr in I2C_ADDR_MIN..=I2C_ADDR_MAX {
        if !running.load(Ordering::SeqCst) {
            return Err("interrupted".into());
        }
        let write_addr = addr << 1;
        let cmd = format!("[{:#04x}]", write_addr);
        let resp = bp_send(&mut *port, &cmd)?;
        let clean = strip_ansi(&resp).to_ascii_lowercase();

        if clean.contains("ack") && !clean.contains("nack") {
            ui::found(&format!("device at {:#04x} (write {:#04x})", addr, write_addr));
            found.push(addr);
        }
    }

    // Return to HiZ
    bp_send(&mut *port, "#")?;

    if found.is_empty() {
        ui::warn("no I2C devices found (check SDA/SCL wiring and pullups)");
    } else {
        ui::win("I2C SCAN", &format!("{} device(s) found", found.len()));
    }

    Ok(found)
}

pub fn i2c_dump(
    port_path: &str,
    device_addr: u8,
    length: u32,
    out_path: &str,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    ui::section("=== I2C EEPROM DUMP (Bus Pirate 5) ===");
    println!("{} {}", "Port:".cyan(), port_path);
    println!("{} device {:#04x}, {} bytes -> {}", "Config:".cyan(), device_addr, length, out_path);

    if device_addr < I2C_ADDR_MIN || device_addr > I2C_ADDR_MAX {
        return Err(format!("device address {:#04x} out of range ({:#04x}-{:#04x})",
            device_addr, I2C_ADDR_MIN, I2C_ADDR_MAX).into());
    }

    let mut port = serialport::new(port_path, BP5_BAUD)
        .timeout(Duration::from_millis(500))
        .open()
        .map_err(|e| format!("open {}: {}", port_path, e))?;

    // Reset to HiZ, select I2C mode
    bp_send(&mut *port, "#")?;
    std::thread::sleep(Duration::from_millis(500));
    bp_send(&mut *port, "m 6")?;
    std::thread::sleep(Duration::from_millis(300));
    bp_send(&mut *port, "1")?;
    std::thread::sleep(Duration::from_millis(200));

    let write_addr = device_addr << 1;
    let read_addr = write_addr | 1;

    // Sequential read: set address pointer to 0, then read N bytes.
    // [write_addr 0x00 0x00 [read_addr r:N]
    // Two address bytes for 16-bit EEPROMs (24C32+), one byte for smaller.
    // We use 16-bit addressing (works for most common EEPROMs).
    ui::step("I2C", "setting address pointer to 0x0000");
    let set_cmd = format!("[{:#04x} 0x00 0x00", write_addr);
    bp_send(&mut *port, &set_cmd)?;

    ui::step("I2C", &format!("reading {} bytes from device {:#04x}", length, device_addr));
    let mut data = Vec::with_capacity(length as usize);
    let chunk_size = 128u32;
    let mut offset = 0u32;

    while offset < length {
        if !running.load(Ordering::SeqCst) {
            return Err("interrupted".into());
        }
        let remaining = length - offset;
        let n = remaining.min(chunk_size);

        // Start condition + read address + read N bytes + stop
        let read_cmd = format!("[{:#04x} r:{}]", read_addr, n);
        let resp = bp_send(&mut *port, &read_cmd)?;
        let clean = strip_ansi(&resp);

        // Parse hex bytes from response: look for "0xNN" patterns
        for word in clean.split_whitespace() {
            if word.starts_with("0x") || word.starts_with("0X") {
                let hex = word.trim_start_matches("0x").trim_start_matches("0X");
                if let Ok(b) = u8::from_str_radix(hex.trim_end_matches(|c: char| !c.is_ascii_hexdigit()), 16) {
                    data.push(b);
                }
            }
        }

        offset += n;
        if !running.load(Ordering::SeqCst) {
            break;
        }
        print!("\r{} {}/{} bytes", "[*]".bold().yellow(), data.len(), length);
    }
    println!();

    // Return to HiZ
    bp_send(&mut *port, "#")?;

    std::fs::write(out_path, &data)?;
    ui::win("I2C DUMP", &format!("{} bytes written to {}", data.len(), out_path));

    Ok(())
}

// ── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ansi_cleans_escapes() {
        let raw = "\x1b[31mhello\x1b[0m world";
        assert_eq!(strip_ansi(raw), "hello world");
    }

    #[test]
    fn address_range_validation() {
        assert!(I2C_ADDR_MIN >= 0x03);
        assert!(I2C_ADDR_MAX <= 0x77);
        assert!(I2C_ADDR_MAX > I2C_ADDR_MIN);
    }

    #[test]
    fn write_addr_shift() {
        // 7-bit addr 0x50 -> write addr 0xA0
        let addr: u8 = 0x50;
        assert_eq!(addr << 1, 0xA0);
        assert_eq!((addr << 1) | 1, 0xA1);
    }
}
