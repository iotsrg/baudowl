// SPI passthrough mode via Bus Pirate 5.
//
// BP5 `m 5` selects SPI mode. Combined with `W` for target power,
// this gives direct SPI access to on-board flash without desoldering.
// baudowl sends raw SPI commands for JEDEC ID, read, write, erase.

use std::error::Error;
use std::io::{self};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use colored::*;

use crate::ui;

const BP5_BAUD: u32 = 115200;
const CMD_TIMEOUT: Duration = Duration::from_secs(2);

// SPI flash standard commands
const CMD_JEDEC_ID: u8 = 0x9F;
const CMD_READ_DATA: u8 = 0x03;

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

pub struct SpiPassOpts {
    pub power: bool,
    pub voltage: f32,
}

impl Default for SpiPassOpts {
    fn default() -> Self {
        Self {
            power: false,
            voltage: 3.3,
        }
    }
}

pub fn spi_identify(
    port_path: &str,
    opts: &SpiPassOpts,
    running: Arc<AtomicBool>,
) -> Result<[u8; 3], Box<dyn Error>> {
    ui::section("=== SPI PASSTHROUGH (Bus Pirate 5) ===");
    println!("{} {}", "Port:".cyan(), port_path);

    let mut port = serialport::new(port_path, BP5_BAUD)
        .timeout(Duration::from_millis(500))
        .open()
        .map_err(|e| format!("open {}: {}", port_path, e))?;

    // Reset to HiZ
    bp_send(&mut *port, "#")?;
    std::thread::sleep(Duration::from_millis(500));

    // Enable power if requested
    if opts.power {
        ui::step("SPI", &format!("enabling {}V target power", opts.voltage));
        bp_send(&mut *port, &format!("W {}", opts.voltage))?;
        std::thread::sleep(Duration::from_millis(300));
    }

    // Select SPI mode
    ui::step("SPI", "configuring BP5 for SPI mode");
    bp_send(&mut *port, "m 5")?;
    std::thread::sleep(Duration::from_millis(300));
    // Speed selection: (4) = 1MHz default
    bp_send(&mut *port, "4")?;
    std::thread::sleep(Duration::from_millis(200));

    if !running.load(Ordering::SeqCst) {
        return Err("interrupted".into());
    }

    // Send JEDEC ID command: CS low, 0x9F, read 3 bytes, CS high
    // BP5 SPI syntax: [ = CS low, ] = CS high, r = read byte
    ui::step("SPI", "reading JEDEC ID");
    let cmd = format!("[0x{:02x} r r r]", CMD_JEDEC_ID);
    let resp = bp_send(&mut *port, &cmd)?;
    let clean = strip_ansi(&resp);

    // Parse the three JEDEC bytes from response
    let mut jedec = [0u8; 3];
    let mut idx = 0;
    for word in clean.split_whitespace() {
        if idx >= 3 { break; }
        let trimmed = word.trim_start_matches("0x").trim_start_matches("0X");
        if trimmed.len() == 2 {
            if let Ok(b) = u8::from_str_radix(
                trimmed.trim_end_matches(|c: char| !c.is_ascii_hexdigit()),
                16,
            ) {
                jedec[idx] = b;
                idx += 1;
            }
        }
    }

    if jedec == [0x00, 0x00, 0x00] || jedec == [0xFF, 0xFF, 0xFF] {
        ui::warn("no flash detected (all zeros or all FF - check wiring)");
    } else {
        ui::found(&format!(
            "JEDEC: manufacturer {:#04x}, type {:#04x}, capacity {:#04x}",
            jedec[0], jedec[1], jedec[2]
        ));
        if let Some(name) = manufacturer_name(jedec[0]) {
            ui::detail(&format!("manufacturer: {}", name));
        }
        let cap = jedec[2];
        if cap >= 0x10 && cap <= 0x1D {
            ui::detail(&format!("capacity: {} bytes", 1u64 << cap));
        }
    }

    // Return to HiZ
    bp_send(&mut *port, "#")?;

    Ok(jedec)
}

pub fn spi_read(
    port_path: &str,
    opts: &SpiPassOpts,
    start: u32,
    length: u32,
    out_path: &str,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    ui::section("=== SPI PASSTHROUGH READ ===");
    println!("{} {:#010x} + {} bytes -> {}", "Range:".cyan(), start, length, out_path);

    let mut port = serialport::new(port_path, BP5_BAUD)
        .timeout(Duration::from_millis(500))
        .open()
        .map_err(|e| format!("open {}: {}", port_path, e))?;

    bp_send(&mut *port, "#")?;
    std::thread::sleep(Duration::from_millis(500));

    if opts.power {
        bp_send(&mut *port, &format!("W {}", opts.voltage))?;
        std::thread::sleep(Duration::from_millis(300));
    }

    bp_send(&mut *port, "m 5")?;
    std::thread::sleep(Duration::from_millis(300));
    bp_send(&mut *port, "4")?;
    std::thread::sleep(Duration::from_millis(200));

    // SPI read: CS low, 0x03 + 24-bit address, then read N bytes, CS high
    // BP5 SPI is slow in text mode, so we chunk the reads.
    let chunk = 64u32;
    let mut data = Vec::with_capacity(length as usize);
    let mut offset = start;

    while offset < start + length {
        if !running.load(Ordering::SeqCst) {
            break;
        }
        let remaining = (start + length) - offset;
        let n = remaining.min(chunk);

        let addr_hi = ((offset >> 16) & 0xFF) as u8;
        let addr_mid = ((offset >> 8) & 0xFF) as u8;
        let addr_lo = (offset & 0xFF) as u8;

        let cmd = format!(
            "[0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x} r:{}]",
            CMD_READ_DATA, addr_hi, addr_mid, addr_lo, n
        );
        let resp = bp_send(&mut *port, &cmd)?;
        let clean = strip_ansi(&resp);

        // Parse read bytes
        let mut count = 0u32;
        for word in clean.split_whitespace() {
            if count >= n { break; }
            let trimmed = word.trim_start_matches("0x").trim_start_matches("0X");
            if trimmed.len() == 2 {
                if let Ok(b) = u8::from_str_radix(
                    trimmed.trim_end_matches(|c: char| !c.is_ascii_hexdigit()),
                    16,
                ) {
                    data.push(b);
                    count += 1;
                }
            }
        }

        offset += n;
        print!("\r{} {}/{} bytes", "[*]".bold().yellow(), data.len(), length);
    }
    println!();

    bp_send(&mut *port, "#")?;

    std::fs::write(out_path, &data)?;
    ui::win("SPI READ", &format!("{} bytes written to {}", data.len(), out_path));

    Ok(())
}

fn manufacturer_name(id: u8) -> Option<&'static str> {
    match id {
        0x01 => Some("Spansion/Cypress"),
        0x1F => Some("Atmel/Microchip"),
        0x20 => Some("ST/Micron/Numonyx"),
        0xBF => Some("SST/Microchip"),
        0xC2 => Some("Macronix"),
        0xC8 => Some("GigaDevice"),
        0xEF => Some("Winbond"),
        _ => None,
    }
}

// ── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_manufacturers() {
        assert_eq!(manufacturer_name(0xEF), Some("Winbond"));
        assert_eq!(manufacturer_name(0xC2), Some("Macronix"));
        assert_eq!(manufacturer_name(0x00), None);
    }

    #[test]
    fn spi_commands_correct() {
        assert_eq!(CMD_JEDEC_ID, 0x9F);
        assert_eq!(CMD_READ_DATA, 0x03);
    }

    #[test]
    fn address_byte_split() {
        let addr: u32 = 0x12_3456;
        assert_eq!(((addr >> 16) & 0xFF) as u8, 0x12);
        assert_eq!(((addr >> 8) & 0xFF) as u8, 0x34);
        assert_eq!((addr & 0xFF) as u8, 0x56);
    }
}
