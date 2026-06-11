//! Passive UART capture and replay. `sniff` reads a line read-only, prints a
//! timestamped hex view, splits the stream into frames by idle gaps, optionally
//! fingerprints the protocol, and saves the raw capture. `replay` sends a saved
//! or crafted byte log back out a port.

use std::error::Error;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use colored::*;

/// Group a timestamped byte stream into frames separated by idle gaps.
/// `events` are (microseconds-since-start, byte); a gap larger than
/// `idle_gap_us` starts a new frame.
pub fn split_frames(events: &[(u64, u8)], idle_gap_us: u64) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    let mut cur = Vec::new();
    let mut last: Option<u64> = None;
    for &(t, b) in events {
        if let Some(lt) = last {
            if t.saturating_sub(lt) > idle_gap_us && !cur.is_empty() {
                frames.push(std::mem::take(&mut cur));
            }
        }
        cur.push(b);
        last = Some(t);
    }
    if !cur.is_empty() {
        frames.push(cur);
    }
    frames
}

fn hex_line(t_us: u64, chunk: &[u8]) -> String {
    let hex = chunk
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    let asc: String = chunk
        .iter()
        .map(|&b| if (0x20..=0x7e).contains(&b) { b as char } else { '.' })
        .collect();
    format!("[+{:>9} us] {:<48} |{}|", t_us, hex, asc)
}

pub struct SniffOpts {
    pub out: Option<String>,
    pub max_bytes: usize,
    pub decode: bool,
    pub idle_gap_us: u64,
    pub reset: Option<String>,
}

/// Pulse a reset on an already-open port so the same handle captures the boot
/// output (no reset/capture race). `esp` is the esptool DTR/RTS sequence.
fn pulse_reset(p: &mut Box<dyn serialport::SerialPort>, profile: &str) {
    match profile.to_ascii_lowercase().as_str() {
        "dtr" => {
            let _ = p.write_data_terminal_ready(true);
            sleep(Duration::from_millis(120));
            let _ = p.write_data_terminal_ready(false);
        }
        "rts" => {
            // hard reset (run app): GPIO0 high via DTR low, pulse the reset line
            let _ = p.write_data_terminal_ready(false);
            let _ = p.write_request_to_send(true);
            sleep(Duration::from_millis(120));
            let _ = p.write_request_to_send(false);
        }
        "esp" => {
            let _ = p.write_data_terminal_ready(false);
            let _ = p.write_request_to_send(true);
            sleep(Duration::from_millis(100));
            let _ = p.write_data_terminal_ready(true);
            let _ = p.write_request_to_send(false);
            sleep(Duration::from_millis(50));
            let _ = p.write_data_terminal_ready(false);
        }
        _ => {}
    }
}

pub fn sniff(
    port: &str,
    baud: u32,
    opts: &SniffOpts,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    println!("\n{}", "=== PASSIVE SNIFF ===".bold().magenta());
    println!(
        "{} {} @ {} baud  (read-only, Ctrl-C to stop)",
        "Target:".cyan(),
        port,
        baud
    );
    let mut p = serialport::new(port, baud)
        .timeout(Duration::from_millis(100))
        .open()
        .map_err(|e| format!("open {}: {}", port, e))?;
    p.clear(serialport::ClearBuffer::All).ok();

    if let Some(profile) = &opts.reset {
        println!("{} pulsing reset ({}) on the open port", "[*]".cyan(), profile);
        pulse_reset(&mut p, profile);
    }

    let start = Instant::now();
    let mut events: Vec<(u64, u8)> = Vec::new();
    let mut raw: Vec<u8> = Vec::new();
    let mut buf = [0u8; 512];
    while running.load(Ordering::SeqCst) && raw.len() < opts.max_bytes {
        match p.read(&mut buf) {
            Ok(n) if n > 0 => {
                let t = start.elapsed().as_micros() as u64;
                for &b in &buf[..n] {
                    events.push((t, b));
                }
                raw.extend_from_slice(&buf[..n]);
                for line in buf[..n].chunks(16) {
                    println!("{}", hex_line(t, line));
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(e.into()),
        }
    }

    let frames = split_frames(&events, opts.idle_gap_us);
    println!(
        "\n{} captured {} bytes in {} frame(s) (idle gap {} us)",
        "[+]".bold().green(),
        raw.len(),
        frames.len(),
        opts.idle_gap_us
    );
    if opts.decode {
        match crate::framing::detect_protocol(&raw) {
            Some(proto) => println!("{} protocol: {}", "[+]".bold().green(), proto.bold()),
            None => println!("{} no known binary protocol", "[-]".dimmed()),
        }
    }
    if let Some(path) = &opts.out {
        std::fs::write(path, &raw)?;
        println!("{} raw capture saved to {}", "[*]".cyan(), path);
    }
    Ok(())
}

/// Send the bytes of a file out the port, chunked with an inter-chunk delay.
pub fn replay(
    port: &str,
    baud: u32,
    path: &str,
    chunk: usize,
    delay_ms: u64,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    println!("\n{}", "=== REPLAY ===".bold().magenta());
    let data = std::fs::read(path)?;
    let mut p = serialport::new(port, baud)
        .timeout(Duration::from_millis(100))
        .open()
        .map_err(|e| format!("open {}: {}", port, e))?;
    println!(
        "{} sending {} bytes from {} to {}",
        "[*]".cyan(),
        data.len(),
        path,
        port
    );
    let mut sent = 0usize;
    for c in data.chunks(chunk.max(1)) {
        if !running.load(Ordering::SeqCst) {
            break;
        }
        p.write_all(c)?;
        p.flush()?;
        sent += c.len();
        if delay_ms > 0 {
            sleep(Duration::from_millis(delay_ms));
        }
    }
    println!("{} replayed {} bytes", "[+]".bold().green(), sent);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_split_on_idle() {
        let ev = vec![(0, 0xa), (10, 0xb), (20, 0xc), (1000, 0xd), (1010, 0xe)];
        let f = split_frames(&ev, 100);
        assert_eq!(f, vec![vec![0xa, 0xb, 0xc], vec![0xd, 0xe]]);
    }

    #[test]
    fn single_frame_when_continuous() {
        let ev: Vec<(u64, u8)> = (0..5).map(|i| (i * 10, i as u8)).collect();
        assert_eq!(split_frames(&ev, 100).len(), 1);
    }

    #[test]
    fn hex_line_format() {
        let l = hex_line(42, &[0x41, 0x00]);
        assert!(l.contains("41 00"));
        assert!(l.contains("|A.|"));
        assert!(l.contains("42 us"));
    }
}
