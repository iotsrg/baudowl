// De Bruijn pattern generator for buffer overflow offset finding.
//
// Generates cyclic patterns where every N-byte subsequence is unique.
// After a crash, the PC/LR value can be looked up to find the exact
// offset from the start of the buffer to the return address.

use std::error::Error;
use std::io::Write as IoWrite;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use colored::*;

use crate::ui;

// Generate a De Bruijn sequence of order N over the given alphabet.
// Each unique N-character substring appears exactly once.
#[cfg(test)]
pub fn de_bruijn(alphabet: &[u8], order: usize) -> Vec<u8> {
    if alphabet.is_empty() || order == 0 {
        return Vec::new();
    }
    let k = alphabet.len();
    let mut sequence = Vec::new();
    let mut a = vec![0usize; k * order + 1];

    fn db(
        t: usize,
        p: usize,
        k: usize,
        n: usize,
        a: &mut Vec<usize>,
        seq: &mut Vec<usize>,
    ) {
        if t > n {
            if n % p == 0 {
                for i in 1..=p {
                    seq.push(a[i]);
                }
            }
        } else {
            a[t] = a[t - p];
            db(t + 1, p, k, n, a, seq);
            for j in (a[t - p] + 1)..k {
                a[t] = j;
                db(t + 1, t, k, n, a, seq);
            }
        }
    }

    let mut indices = Vec::new();
    db(1, 1, k, order, &mut a, &mut indices);

    for &idx in &indices {
        sequence.push(alphabet[idx]);
    }

    sequence
}

// Generate a cyclic pattern of exactly `length` bytes.
// Uses a 3-character alphabet (uppercase, lowercase, digit) with order 4,
// giving unique 4-byte subsequences for offset finding.
pub fn cyclic_pattern(length: usize) -> Vec<u8> {
    let upper: Vec<u8> = (b'A'..=b'Z').collect();
    let lower: Vec<u8> = (b'a'..=b'z').collect();
    let digit: Vec<u8> = (b'0'..=b'9').collect();

    let mut pattern = Vec::with_capacity(length);

    // Generate pattern: Aa0A, Aa1A, Aa2A, ... Ab0A, etc.
    // This gives unique 4-byte subsequences up to 26*26*10*26 = 175760 bytes.
    'outer: for &u in &upper {
        for &l in &lower {
            for &d in &digit {
                for &u2 in &upper {
                    if pattern.len() >= length {
                        break 'outer;
                    }
                    pattern.push(u);
                    if pattern.len() >= length { break 'outer; }
                    pattern.push(l);
                    if pattern.len() >= length { break 'outer; }
                    pattern.push(d);
                    if pattern.len() >= length { break 'outer; }
                    pattern.push(u2);
                }
            }
        }
    }

    pattern
}

// Find the offset of a 4-byte value in the cyclic pattern.
// The value can be given as a hex string (e.g., "0x41306141") or raw bytes.
pub fn pattern_offset(value: u32, length: usize) -> Option<usize> {
    let pattern = cyclic_pattern(length);
    let needle = value.to_le_bytes();

    if pattern.len() < 4 {
        return None;
    }

    for i in 0..=(pattern.len() - 4) {
        if pattern[i] == needle[0]
            && pattern[i + 1] == needle[1]
            && pattern[i + 2] == needle[2]
            && pattern[i + 3] == needle[3]
        {
            return Some(i);
        }
    }
    None
}

pub enum PatternOp {
    Generate { length: usize },
    Find { value: u32, length: usize },
    Send { length: usize },
}

pub fn pattern_flow(
    port_path: &str,
    baud: u32,
    op: PatternOp,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    match op {
        PatternOp::Generate { length } => {
            ui::section("=== PATTERN GENERATE ===");
            let pat = cyclic_pattern(length);
            println!("{}", String::from_utf8_lossy(&pat));
            ui::win("PATTERN", &format!("{} bytes generated", pat.len()));
        }
        PatternOp::Find { value, length } => {
            ui::section("=== PATTERN OFFSET ===");
            println!("{} searching for {:#010x} in {} byte pattern", "Query:".cyan(), value, length);
            match pattern_offset(value, length) {
                Some(off) => {
                    ui::found(&format!(
                        "exact offset: {} (0x{:x}) bytes from buffer start",
                        off, off
                    ));
                }
                None => {
                    ui::warn("value not found in pattern (try a larger --pattern-length)");
                    // Try little-endian swap
                    let swapped = value.swap_bytes();
                    if let Some(off) = pattern_offset(swapped, length) {
                        ui::found(&format!(
                            "byte-swapped match at offset {} (0x{:x}) - target may be big-endian",
                            off, off
                        ));
                    }
                }
            }
        }
        PatternOp::Send { length } => {
            ui::section("=== PATTERN INJECT ===");
            println!("{} {} @ {} baud", "Port:".cyan(), port_path, baud);
            println!("{} sending {} byte cyclic pattern", "Config:".cyan(), length);

            let pat = cyclic_pattern(length);

            let mut port = serialport::new(port_path, baud)
                .timeout(Duration::from_millis(500))
                .open()
                .map_err(|e| format!("open {}: {}", port_path, e))?;

            // Send in chunks to avoid overwhelming slow UARTs
            let chunk_size = 256;
            let mut sent = 0;
            for chunk in pat.chunks(chunk_size) {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                port.write_all(chunk)?;
                port.flush()?;
                sent += chunk.len();
                print!("\r{} {}/{} bytes sent", "[*]".bold().yellow(), sent, length);
                std::thread::sleep(Duration::from_millis(10));
            }
            println!();

            // Read any crash response
            std::thread::sleep(Duration::from_millis(500));
            let mut resp = [0u8; 4096];
            let mut total = Vec::new();
            while let Ok(n) = port.read(&mut resp) {
                if n == 0 { break; }
                total.extend_from_slice(&resp[..n]);
                if total.len() > 4096 { break; }
            }

            if !total.is_empty() {
                ui::detail(&format!("response: {} bytes", total.len()));
                let preview: String = total.iter()
                    .take(128)
                    .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                    .collect();
                ui::detail(&format!("  {}", preview));
            }

            ui::win("PATTERN INJECT", &format!("{} bytes sent", sent));
        }
    }
    Ok(())
}

// ── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cyclic_pattern_length() {
        let pat = cyclic_pattern(100);
        assert_eq!(pat.len(), 100);
        let pat = cyclic_pattern(1000);
        assert_eq!(pat.len(), 1000);
    }

    #[test]
    fn cyclic_pattern_unique_subsequences() {
        let pat = cyclic_pattern(1000);
        // Every 4-byte subsequence should be unique
        let mut seen = std::collections::HashSet::new();
        for i in 0..=(pat.len() - 4) {
            let sub = &pat[i..i + 4];
            let key = u32::from_le_bytes([sub[0], sub[1], sub[2], sub[3]]);
            assert!(seen.insert(key), "duplicate at offset {}", i);
        }
    }

    #[test]
    fn pattern_offset_roundtrip() {
        let pat = cyclic_pattern(2000);
        // Pick a value from offset 100
        let val = u32::from_le_bytes([pat[100], pat[101], pat[102], pat[103]]);
        assert_eq!(pattern_offset(val, 2000), Some(100));
    }

    #[test]
    fn pattern_offset_start() {
        let pat = cyclic_pattern(500);
        let val = u32::from_le_bytes([pat[0], pat[1], pat[2], pat[3]]);
        assert_eq!(pattern_offset(val, 500), Some(0));
    }

    #[test]
    fn pattern_all_printable() {
        let pat = cyclic_pattern(5000);
        for (i, &b) in pat.iter().enumerate() {
            assert!(
                b.is_ascii_alphanumeric(),
                "non-alphanumeric byte {:#04x} at offset {}",
                b,
                i
            );
        }
    }

    #[test]
    fn de_bruijn_basic() {
        let seq = de_bruijn(b"01", 3);
        // De Bruijn sequence B(2,3) has length 2^3 = 8
        assert_eq!(seq.len(), 8);
    }
}
