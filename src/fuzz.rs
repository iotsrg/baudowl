//! Serial-driven fuzzer with a crash oracle, auto-reset, and test-case
//! minimization. Sends generated/mutated input to a console or protocol
//! parser, detects crashes from the serial output (panic strings, aborts,
//! resets), resets the target over DTR/RTS or a command, and shrinks the
//! crashing input to a minimal deterministic repro via delta debugging.

use std::collections::HashSet;
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use colored::*;

use crate::session::Session;

/// Deterministic xorshift64 PRNG so a fuzzing run is reproducible from a seed.
pub struct Prng {
    s: u64,
}

impl Prng {
    pub fn new(seed: u64) -> Self {
        Self {
            s: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed },
        }
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.s;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.s = x;
        x
    }
    pub fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
}

/// A fresh random test case of length 1..=max_len.
pub fn gen_case(prng: &mut Prng, max_len: usize) -> Vec<u8> {
    let len = 1 + prng.below(max_len.max(1));
    (0..len).map(|_| prng.byte()).collect()
}

/// Mutate a seed input with a few random edits (set, bit flip, insert, delete).
pub fn mutate(seed: &[u8], prng: &mut Prng, max_len: usize) -> Vec<u8> {
    if seed.is_empty() {
        return gen_case(prng, max_len);
    }
    let mut out = seed.to_vec();
    let n = 1 + prng.below(4);
    for _ in 0..n {
        match prng.below(4) {
            0 => {
                let i = prng.below(out.len());
                out[i] = prng.byte();
            }
            1 => {
                let i = prng.below(out.len());
                out[i] ^= 1 << prng.below(8);
            }
            2 if out.len() < max_len => {
                let i = prng.below(out.len() + 1);
                out.insert(i, prng.byte());
            }
            _ if out.len() > 1 => {
                let i = prng.below(out.len());
                out.remove(i);
            }
            _ => {}
        }
    }
    out
}

/// Protocol shape for structure-aware case generation.
#[derive(Clone, Copy)]
pub enum Proto {
    Raw,
    Modbus,
    Nmea,
}

impl Proto {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "modbus" => Self::Modbus,
            "nmea" => Self::Nmea,
            _ => Self::Raw,
        }
    }
}

/// Generate a protocol-shaped case: a valid frame, sometimes field-corrupted,
/// to exercise a parser's structure handling instead of pure random bytes.
pub fn gen_protocol_case(proto: Proto, prng: &mut Prng, max_len: usize) -> Vec<u8> {
    match proto {
        Proto::Raw => gen_case(prng, max_len),
        Proto::Modbus => {
            let addr = (prng.below(247) + 1) as u8;
            let funcs = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0f, 0x10];
            let func = funcs[prng.below(funcs.len())];
            let dlen = prng.below(8);
            let data: Vec<u8> = (0..dlen).map(|_| prng.byte()).collect();
            let mut f = crate::framing::modbus_frame(addr, func, &data);
            if prng.below(2) == 0 && !f.is_empty() {
                let i = prng.below(f.len());
                f[i] = f[i].wrapping_add(1 + prng.byte());
            }
            f
        }
        Proto::Nmea => {
            const SET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ,.-";
            let n = prng.below(40) + 4;
            let body: String = (0..n).map(|_| SET[prng.below(SET.len())] as char).collect();
            let mut s = crate::framing::nmea_sentence(&format!("GP{}", body)).into_bytes();
            if prng.below(2) == 0 && !s.is_empty() {
                let i = prng.below(s.len());
                s[i] = s[i].wrapping_add(1);
            }
            s
        }
    }
}

/// Default substrings that indicate a target crashed/reset.
pub fn default_crash_signatures() -> Vec<String> {
    [
        "kernel panic",
        "unable to handle",
        "data abort",
        "prefetch abort",
        "undefined instruction",
        "segmentation fault",
        "stack smashing",
        "*** buffer overflow",
        "watchdog",
        "rst:0x",
        "exception",
        "oops",
        "call trace",
        "guru meditation",
        "assertion failed",
        "abort()",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

pub fn looks_like_crash(output: &str, sigs: &[String]) -> bool {
    let low = output.to_ascii_lowercase();
    sigs.iter().any(|s| low.contains(&s.to_ascii_lowercase()))
}

/// Delta-debug `input` down to a minimal subset for which `still_fails` is true.
/// Removes shrinking-size chunks and keeps any removal that preserves failure.
pub fn minimize<F: FnMut(&[u8]) -> bool>(input: &[u8], mut still_fails: F) -> Vec<u8> {
    let mut data = input.to_vec();
    let mut chunk = (data.len() / 2).max(1);
    loop {
        let mut i = 0;
        let mut shrank = false;
        while i < data.len() {
            let end = (i + chunk).min(data.len());
            let mut cand = Vec::with_capacity(data.len() - (end - i));
            cand.extend_from_slice(&data[..i]);
            cand.extend_from_slice(&data[end..]);
            if !cand.is_empty() && still_fails(&cand) {
                data = cand;
                shrank = true;
            } else {
                i += chunk;
            }
        }
        if chunk == 1 {
            if !shrank {
                break;
            }
        } else {
            chunk = (chunk / 2).max(1);
        }
    }
    data
}

pub fn to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

#[derive(Clone, Copy)]
pub enum ResetMode {
    Dtr,
    Rts,
    Cmd,
    None,
}

impl ResetMode {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "dtr" => Self::Dtr,
            "rts" => Self::Rts,
            "cmd" => Self::Cmd,
            _ => Self::None,
        }
    }
}

pub struct FuzzOpts {
    pub seed_input: Vec<u8>,
    pub max_len: usize,
    pub iterations: usize,
    pub response_timeout: Duration,
    pub crash_sigs: Vec<String>,
    pub reset: ResetMode,
    pub reset_cmd: Option<String>,
    pub seed: u64,
    pub newline: bool,
    pub proto: Proto,
}

fn send_and_crashed(
    s: &mut Session,
    case: &[u8],
    newline: bool,
    timeout: Duration,
    sigs: &[String],
) -> bool {
    let start = s.log.len();
    let _ = s.send(case);
    if newline {
        let _ = s.send(b"\r");
    }
    s.collect(timeout);
    let out = String::from_utf8_lossy(&s.log[start..]);
    looks_like_crash(&out, sigs)
}

fn do_reset(s: &mut Session, mode: ResetMode, reset_cmd: &Option<String>) {
    match mode {
        ResetMode::None => return, // auto-recovering target, no reset or wait
        ResetMode::Dtr => {
            let _ = s.set_dtr(true);
            sleep(Duration::from_millis(120));
            let _ = s.set_dtr(false);
        }
        ResetMode::Rts => {
            let _ = s.set_rts(true);
            sleep(Duration::from_millis(120));
            let _ = s.set_rts(false);
        }
        ResetMode::Cmd => {
            if let Some(c) = reset_cmd {
                let _ = s.send_line(c);
            }
        }
    }
    s.collect(Duration::from_millis(300));
}

/// Run the fuzzing loop. Returns the minimized crashing inputs (deduplicated).
pub fn run_fuzz(
    port: &str,
    baud: u32,
    opts: &FuzzOpts,
    running: Arc<AtomicBool>,
) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    println!("\n{}", "=== SERIAL FUZZER ===".bold().magenta());
    println!(
        "{} {} @ {} baud  iterations={} max_len={} seed={}",
        "Target:".cyan(),
        port,
        baud,
        opts.iterations,
        opts.max_len,
        opts.seed
    );
    let mut s = Session::open(port, baud, running.clone())?;
    s.echo = false;
    s.collect(Duration::from_millis(300));
    let mut prng = Prng::new(opts.seed);
    let mut crashes: Vec<Vec<u8>> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();

    for i in 0..opts.iterations {
        if !running.load(Ordering::SeqCst) {
            break;
        }
        let case = if !opts.seed_input.is_empty() {
            mutate(&opts.seed_input, &mut prng, opts.max_len)
        } else {
            gen_protocol_case(opts.proto, &mut prng, opts.max_len)
        };
        if send_and_crashed(&mut s, &case, opts.newline, opts.response_timeout, &opts.crash_sigs) {
            println!(
                "\n{} crash at iteration {} with {} bytes",
                "[!]".bold().red(),
                i,
                case.len()
            );
            do_reset(&mut s, opts.reset, &opts.reset_cmd);
            let sigs = &opts.crash_sigs;
            let rt = opts.response_timeout;
            let nl = opts.newline;
            let mode = opts.reset;
            let rcmd = &opts.reset_cmd;
            let minimized = minimize(&case, |cand| {
                let crashed = send_and_crashed(&mut s, cand, nl, rt, sigs);
                if crashed {
                    do_reset(&mut s, mode, rcmd);
                }
                crashed
            });
            if seen.insert(minimized.clone()) {
                println!(
                    "{} minimized to {} byte(s): {}",
                    "[+]".bold().green(),
                    minimized.len(),
                    to_hex(&minimized)
                );
                crashes.push(minimized);
            }
        }
    }
    println!("\n{} {} unique crash(es) found", "[+]".bold().green(), crashes.len());
    Ok(crashes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prng_is_deterministic() {
        let mut a = Prng::new(42);
        let mut b = Prng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        assert_ne!(Prng::new(1).next_u64(), Prng::new(2).next_u64());
    }

    #[test]
    fn crash_signature_match() {
        let sigs = default_crash_signatures();
        assert!(looks_like_crash("... Kernel panic - not syncing ...", &sigs));
        assert!(looks_like_crash("Data Abort at 0xdeadbeef", &sigs));
        assert!(!looks_like_crash("login: ok\n# ", &sigs));
    }

    #[test]
    fn minimize_to_content_trigger() {
        // predicate: crashes only if the adjacent pair DE AD is present
        let mut input = vec![0u8; 20];
        input.extend_from_slice(&[0xDE, 0xAD]);
        input.extend_from_slice(&[0u8; 28]);
        let out = minimize(&input, |c| c.windows(2).any(|w| w == [0xDE, 0xAD]));
        assert_eq!(out, vec![0xDE, 0xAD]);
    }

    #[test]
    fn minimize_to_length_trigger() {
        // predicate: crashes if length >= 8
        let input: Vec<u8> = (0..40).collect();
        let out = minimize(&input, |c| c.len() >= 8);
        assert_eq!(out.len(), 8);
    }

    #[test]
    fn protocol_gen_modbus_is_framed() {
        let mut prng = Prng::new(3);
        let mut any_valid = false;
        for _ in 0..20 {
            let c = gen_protocol_case(Proto::Modbus, &mut prng, 32);
            if crate::framing::detect_protocol(&c) == Some("Modbus RTU") {
                any_valid = true;
            }
        }
        assert!(any_valid);
    }

    #[test]
    fn mutate_stays_in_bounds() {
        let mut prng = Prng::new(7);
        let seed = vec![1, 2, 3, 4];
        for _ in 0..200 {
            let m = mutate(&seed, &mut prng, 8);
            assert!(!m.is_empty() && m.len() <= 8);
        }
    }
}
