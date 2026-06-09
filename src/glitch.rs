//! Glitch-trigger coordination. Watch the serial stream for a marker and, the
//! instant it appears, fire a trigger so a fault-injection rig can act at a
//! known point in the boot flow. The trigger is a pulse on RTS or DTR and/or an
//! external command (for example a ChipWhisperer script).
//!
//! Note: pulse width here is bounded by OS scheduler granularity. For tight
//! glitch timing, use `--glitch-cmd` to hand off to a real timing rig; the
//! serial line pulse is for coarse triggering.

use std::error::Error;
use std::io::Read;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use colored::*;

#[derive(Clone, Copy)]
pub enum TriggerLine {
    Rts,
    Dtr,
    None,
}

impl TriggerLine {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "rts" => Self::Rts,
            "dtr" => Self::Dtr,
            _ => Self::None,
        }
    }
}

pub struct GlitchOpts {
    pub pattern: String,
    pub line: TriggerLine,
    pub pulse_us: u64,
    pub command: Option<String>,
    pub timeout: Duration,
}

/// Watch the line until `pattern` appears, then fire the trigger. Returns
/// `true` if the pattern was seen and the trigger fired.
pub fn watch_and_trigger(
    port: &str,
    baud: u32,
    opts: &GlitchOpts,
    running: Arc<AtomicBool>,
) -> Result<bool, Box<dyn Error>> {
    println!("\n{}", "=== GLITCH TRIGGER ===".bold().magenta());
    let mut p = serialport::new(port, baud)
        .timeout(Duration::from_millis(50))
        .open()
        .map_err(|e| format!("open {}: {}", port, e))?;
    match opts.line {
        TriggerLine::Rts => {
            p.write_request_to_send(false).ok();
        }
        TriggerLine::Dtr => {
            p.write_data_terminal_ready(false).ok();
        }
        TriggerLine::None => {}
    }

    println!("{} watching for {:?}...", "[*]".cyan(), opts.pattern);
    let deadline = Instant::now() + opts.timeout;
    let needle = opts.pattern.to_ascii_lowercase();
    let mut window = String::new();
    let mut buf = [0u8; 512];
    while Instant::now() < deadline && running.load(Ordering::SeqCst) {
        match p.read(&mut buf) {
            Ok(n) if n > 0 => {
                for &b in &buf[..n] {
                    window.push(if (0x20..=0x7e).contains(&b) || b == b'\n' {
                        b as char
                    } else {
                        '.'
                    });
                }
                if window.len() > 4096 {
                    let cut = window.len() - 4096;
                    window = window.split_off(cut);
                }
                if window.to_ascii_lowercase().contains(&needle) {
                    println!("\n{} pattern hit, firing trigger", "[!]".bold().red());
                    fire(p.as_mut(), opts);
                    return Ok(true);
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(e.into()),
        }
    }
    println!("{}", "pattern not seen before timeout".yellow());
    Ok(false)
}

fn fire(p: &mut dyn serialport::SerialPort, opts: &GlitchOpts) {
    match opts.line {
        TriggerLine::Rts => {
            p.write_request_to_send(true).ok();
            sleep(Duration::from_micros(opts.pulse_us));
            p.write_request_to_send(false).ok();
        }
        TriggerLine::Dtr => {
            p.write_data_terminal_ready(true).ok();
            sleep(Duration::from_micros(opts.pulse_us));
            p.write_data_terminal_ready(false).ok();
        }
        TriggerLine::None => {}
    }
    if let Some(cmd) = &opts.command {
        println!("{} running glitch command: {}", "[*]".cyan(), cmd);
        match Command::new("sh").arg("-c").arg(cmd).status() {
            Ok(st) => println!("{} command exited: {}", "[*]".cyan(), st),
            Err(e) => println!("{} command failed: {}", "[!]".red(), e),
        }
    }
}
