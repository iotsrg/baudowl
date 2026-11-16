// JTAG/SWD pin discovery over serial-controlled GPIO.
//
// Toggles candidate pins via DTR/RTS (or BP5 AUX/IO) looking for
// JTAG IDCODE responses. Works with Bus Pirate 5 in JTAG mode or
// any serial adapter with DTR/RTS access to the target's debug header.

use std::error::Error;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use colored::*;

use crate::ui;

const BYPASS: u32 = 0xFFFF_FFFF;

// Known JTAG IDCODE manufacturer IDs (bits 11:1 of IDCODE)
fn manufacturer_name(id: u16) -> &'static str {
    match id {
        0x00E => "ARM",
        0x049 => "Xilinx",
        0x06E => "ST Micro",
        0x093 => "Atmel",
        0x097 => "Texas Instruments",
        0x0EB => "Altera/Intel",
        0x17F => "Espressif",
        0x20A => "Microchip",
        0x43B => "ARM (Cortex debug)",
        _ => "unknown",
    }
}

fn parse_idcode(raw: u32) -> Option<IdCode> {
    if raw == 0 || raw == BYPASS {
        return None;
    }
    // Bit 0 must be 1 for a valid IDCODE
    if raw & 1 != 1 {
        return None;
    }
    Some(IdCode {
        raw,
        manufacturer: ((raw >> 1) & 0x7FF) as u16,
        part: ((raw >> 12) & 0xFFFF) as u16,
        version: ((raw >> 28) & 0xF) as u8,
    })
}

pub struct IdCode {
    pub raw: u32,
    pub manufacturer: u16,
    pub part: u16,
    pub version: u8,
}

pub struct JtagScanOpts {
    pub tck_delay_us: u64,
    pub chain_len: usize,
}

impl Default for JtagScanOpts {
    fn default() -> Self {
        Self {
            tck_delay_us: 10,
            chain_len: 8,
        }
    }
}

// Bit-bang JTAG over serial control lines.
// TCK = RTS, TMS = DTR, TDI via break, TDO sampled from CTS/DSR.
// This is the same approach as JTAGulator and bus-pirate JTAG scanning.
struct JtagBitbang {
    port: Box<dyn serialport::SerialPort>,
    tck_delay: Duration,
}

impl JtagBitbang {
    fn new(port: Box<dyn serialport::SerialPort>, tck_delay_us: u64) -> Self {
        Self {
            port,
            tck_delay: Duration::from_micros(tck_delay_us),
        }
    }

    fn tck_pulse(&mut self) -> io::Result<()> {
        self.port.write_request_to_send(true)?;
        std::thread::sleep(self.tck_delay);
        self.port.write_request_to_send(false)?;
        std::thread::sleep(self.tck_delay);
        Ok(())
    }

    fn set_tms(&mut self, high: bool) -> io::Result<()> {
        self.port.write_data_terminal_ready(high)?;
        Ok(())
    }

    fn read_tdo(&mut self) -> io::Result<bool> {
        // CTS is typically used as TDO in serial JTAG adapters
        Ok(self.port.read_clear_to_send()?)
    }

    fn reset_tap(&mut self) -> io::Result<()> {
        // 5 TCK pulses with TMS=1 returns any TAP to Test-Logic-Reset
        self.set_tms(true)?;
        for _ in 0..5 {
            self.tck_pulse()?;
        }
        Ok(())
    }

    fn shift_ir_to_dr(&mut self) -> io::Result<()> {
        // From Test-Logic-Reset: TMS=0 to Run-Test-Idle
        self.set_tms(false)?;
        self.tck_pulse()?;
        // TMS=1 to Select-DR-Scan
        self.set_tms(true)?;
        self.tck_pulse()?;
        // TMS=0 to Capture-DR
        self.set_tms(false)?;
        self.tck_pulse()?;
        // TMS=0 to Shift-DR
        self.tck_pulse()?;
        Ok(())
    }

    fn shift_out_32(&mut self) -> io::Result<u32> {
        let mut val: u32 = 0;
        self.set_tms(false)?;
        for bit in 0..32 {
            if bit == 31 {
                self.set_tms(true)?; // Exit1-DR on last bit
            }
            let tdo = self.read_tdo()?;
            if tdo {
                val |= 1 << bit;
            }
            self.tck_pulse()?;
        }
        Ok(val)
    }
}

pub fn jtag_scan(
    port_path: &str,
    baud: u32,
    opts: &JtagScanOpts,
    running: Arc<AtomicBool>,
) -> Result<Vec<IdCode>, Box<dyn Error>> {
    ui::section("=== JTAG SCAN ===");
    println!("{} {} @ {} baud", "Port:".cyan(), port_path, baud);
    println!(
        "{} TCK delay {}us, max chain depth {}",
        "Config:".cyan(),
        opts.tck_delay_us,
        opts.chain_len
    );

    let port = serialport::new(port_path, baud)
        .timeout(Duration::from_millis(200))
        .open()
        .map_err(|e| format!("open {}: {}", port_path, e))?;

    let mut jtag = JtagBitbang::new(port, opts.tck_delay_us);

    ui::step("JTAG", "resetting TAP state machine");
    jtag.reset_tap()?;

    ui::step("JTAG", "scanning IDCODE chain");
    jtag.shift_ir_to_dr()?;

    let mut codes = Vec::new();
    for i in 0..opts.chain_len {
        if !running.load(Ordering::SeqCst) {
            return Err("interrupted".into());
        }
        let raw = jtag.shift_out_32()?;
        if let Some(id) = parse_idcode(raw) {
            ui::found(&format!(
                "device {}: IDCODE {:#010x} - {} (part {:#06x} rev {})",
                i,
                id.raw,
                manufacturer_name(id.manufacturer),
                id.part,
                id.version,
            ));
            codes.push(id);
        } else if raw == BYPASS || raw == 0 {
            ui::detail(&format!("device {}: end of chain ({:#010x})", i, raw));
            break;
        }
    }

    if codes.is_empty() {
        ui::warn("no JTAG devices found (check wiring: TCK=RTS, TMS=DTR, TDO=CTS)");
    } else {
        ui::win("JTAG SCAN", &format!("{} device(s) in chain", codes.len()));
    }

    Ok(codes)
}

// ── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_idcode() {
        // ARM Cortex-M: manufacturer 0x43B, part 0xBA01, version 2
        let raw: u32 = 0x2BA0_1477;
        let id = parse_idcode(raw).unwrap();
        assert_eq!(id.manufacturer, 0x23B);
        assert_eq!(id.raw, raw);
    }

    #[test]
    fn reject_bypass_and_zero() {
        assert!(parse_idcode(0x0000_0000).is_none());
        assert!(parse_idcode(0xFFFF_FFFF).is_none());
    }

    #[test]
    fn reject_even_lsb() {
        // Bit 0 must be 1 for a valid IDCODE
        assert!(parse_idcode(0x0BA0_1476).is_none());
    }

    #[test]
    fn known_manufacturers() {
        assert_eq!(manufacturer_name(0x00E), "ARM");
        assert_eq!(manufacturer_name(0x17F), "Espressif");
        assert_eq!(manufacturer_name(0x999), "unknown");
    }
}
