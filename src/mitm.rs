//! UART man-in-the-middle. Bridge two serial ports (A = target, B = host),
//! forward bytes both directions, log them, and optionally rewrite bytes in
//! transit with directional find/replace rules. Wire the tool inline on the
//! TX/RX pair to intercept and tamper with a live link.

use std::error::Error;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use colored::*;

use serialport::SerialPort;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dir {
    AtoB,
    BtoA,
    Both,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub dir: Dir,
    pub find: Vec<u8>,
    pub replace: Vec<u8>,
}

/// Replace every non-overlapping occurrence of `find` with `replace`.
fn replace_bytes(data: &[u8], find: &[u8], rep: &[u8]) -> Vec<u8> {
    if find.is_empty() {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if i + find.len() <= data.len() && &data[i..i + find.len()] == find {
            out.extend_from_slice(rep);
            i += find.len();
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    out
}

/// Apply all rules that match `dir` (or are bidirectional) to `data`.
pub fn apply_rules(data: &[u8], rules: &[Rule], dir: Dir) -> Vec<u8> {
    let mut out = data.to_vec();
    for r in rules {
        if r.dir == dir || r.dir == Dir::Both {
            out = replace_bytes(&out, &r.find, &r.replace);
        }
    }
    out
}

fn open(port: &str, baud: u32) -> Result<Box<dyn SerialPort>, Box<dyn Error>> {
    serialport::new(port, baud)
        .timeout(Duration::from_millis(50))
        .open()
        .map_err(|e| format!("open {}: {}", port, e).into())
}

fn pump(
    mut reader: Box<dyn SerialPort>,
    mut writer: Box<dyn SerialPort>,
    rules: Vec<Rule>,
    dir: Dir,
    running: Arc<AtomicBool>,
    label: &str,
) {
    let mut buf = [0u8; 512];
    while running.load(Ordering::SeqCst) {
        match reader.read(&mut buf) {
            Ok(n) if n > 0 => {
                let out = apply_rules(&buf[..n], &rules, dir);
                let _ = writer.write_all(&out);
                let _ = writer.flush();
                let changed = if out != buf[..n] { " (rewritten)" } else { "" };
                println!(
                    "{} {} {} byte(s){}",
                    label.bold().cyan(),
                    "->".dimmed(),
                    out.len(),
                    changed.yellow()
                );
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
}

/// Bridge `port_a` and `port_b`, applying `rules` in transit.
pub fn mitm(
    port_a: &str,
    port_b: &str,
    baud: u32,
    rules: Vec<Rule>,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    println!("\n{}", "=== UART MITM BRIDGE ===".bold().magenta());
    println!(
        "{} A={} <-> B={} @ {} baud  rules={}",
        "Target:".cyan(),
        port_a,
        port_b,
        baud,
        rules.len()
    );
    let a_reader = open(port_a, baud)?;
    let a_writer = a_reader.try_clone()?;
    let b_reader = open(port_b, baud)?;
    let b_writer = b_reader.try_clone()?;

    let r1 = running.clone();
    let rules1 = rules.clone();
    let handle = thread::spawn(move || pump(a_reader, b_writer, rules1, Dir::AtoB, r1, "A>B"));
    pump(b_reader, a_writer, rules, Dir::BtoA, running, "B>A");
    let _ = handle.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_rewrite_directionally() {
        let rules = vec![Rule {
            dir: Dir::AtoB,
            find: b"DEAD".to_vec(),
            replace: b"BEEF".to_vec(),
        }];
        assert_eq!(apply_rules(b"xDEADy", &rules, Dir::AtoB), b"xBEEFy");
        // wrong direction leaves data untouched
        assert_eq!(apply_rules(b"xDEADy", &rules, Dir::BtoA), b"xDEADy");
    }

    #[test]
    fn replace_changes_length() {
        let rules = vec![Rule {
            dir: Dir::Both,
            find: vec![0xff],
            replace: vec![0x00, 0x00],
        }];
        assert_eq!(
            apply_rules(&[0xff, 0x01, 0xff], &rules, Dir::AtoB),
            vec![0x00, 0x00, 0x01, 0x00, 0x00]
        );
    }

    #[test]
    fn empty_find_is_noop() {
        let rules = vec![Rule {
            dir: Dir::Both,
            find: vec![],
            replace: vec![0x41],
        }];
        assert_eq!(apply_rules(b"abc", &rules, Dir::AtoB), b"abc");
    }
}
