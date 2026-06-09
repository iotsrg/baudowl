//! A small expect-style scripting DSL run over the serial Session.
//! One command per line; comments start with `#`:
//!   send <text>          send text plus CR (escapes: \n \r \t \xNN)
//!   sendraw <hex>        send raw bytes, e.g. `sendraw de ad be ef`
//!   expect [secs] <pat>  wait for a substring (default 10s)
//!   delay <ms>           read/drain for a fixed time
//!   log <message>        print a line

use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use colored::*;

use crate::session::Session;

#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Send(String),
    SendRaw(Vec<u8>),
    Expect { pattern: String, timeout: Duration },
    Delay(Duration),
    Log(String),
}

fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some('x') => {
                let a = chars.next();
                let b = chars.next();
                if let (Some(a), Some(b)) = (a, b) {
                    if let Ok(v) = u8::from_str_radix(&format!("{}{}", a, b), 16) {
                        out.push(v as char);
                    }
                }
            }
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() || (cleaned.len() & 1) != 0 {
        return Err("hex must be non-empty and even length".to_string());
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|_| format!("bad hex byte '{}'", &cleaned[i..i + 2]))
        })
        .collect()
}

/// If `arg` starts with an integer, treat it as a seconds timeout and return
/// the remainder as the pattern; otherwise default to 10 seconds.
fn split_timeout(arg: &str) -> (Duration, &str) {
    if let Some((first, rest)) = arg.split_once(char::is_whitespace) {
        if let Ok(secs) = first.parse::<u64>() {
            return (Duration::from_secs(secs), rest.trim());
        }
    }
    (Duration::from_secs(10), arg)
}

pub fn parse_script(text: &str) -> Result<Vec<Step>, String> {
    let mut steps = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (cmd, arg) = match line.split_once(char::is_whitespace) {
            Some((c, a)) => (c, a.trim()),
            None => (line, ""),
        };
        let step = match cmd.to_ascii_lowercase().as_str() {
            "send" => Step::Send(unescape(arg)),
            "sendraw" => Step::SendRaw(parse_hex(arg).map_err(|e| format!("line {}: {}", n + 1, e))?),
            "expect" => {
                let (timeout, pattern) = split_timeout(arg);
                if pattern.is_empty() {
                    return Err(format!("line {}: expect needs a pattern", n + 1));
                }
                Step::Expect { pattern: unescape(pattern), timeout }
            }
            "delay" => {
                let ms: u64 = arg
                    .parse()
                    .map_err(|_| format!("line {}: delay needs milliseconds", n + 1))?;
                Step::Delay(Duration::from_millis(ms))
            }
            "log" => Step::Log(arg.to_string()),
            other => return Err(format!("line {}: unknown command '{}'", n + 1, other)),
        };
        steps.push(step);
    }
    Ok(steps)
}

pub fn run_script(
    port: &str,
    baud: u32,
    steps: &[Step],
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    println!("\n{}", "=== SCRIPT ===".bold().magenta());
    let mut s = Session::open(port, baud, running.clone())?;
    s.echo = true;
    for (i, step) in steps.iter().enumerate() {
        if !running.load(Ordering::SeqCst) {
            break;
        }
        match step {
            Step::Send(t) => {
                println!("{} send {:?}", "[>]".cyan(), t);
                s.send_line(t)?;
            }
            Step::SendRaw(b) => {
                println!("{} sendraw {} bytes", "[>]".cyan(), b.len());
                s.send(b)?;
            }
            Step::Expect { pattern, timeout } => {
                println!("{} expect {:?} ({}s)", "[?]".yellow(), pattern, timeout.as_secs());
                if s.expect(std::slice::from_ref(pattern), *timeout).is_none() {
                    return Err(format!("step {}: timed out waiting for {:?}", i + 1, pattern).into());
                }
                println!("{} matched", "[+]".green());
            }
            Step::Delay(d) => {
                s.collect(*d);
            }
            Step::Log(m) => println!("{} {}", "[*]".bold(), m),
        }
    }
    println!("{}", "script complete".green());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_script() {
        let src = "# comment\nsend hello\nexpect 5 login:\nsendraw de ad\ndelay 100\nlog done\n";
        let steps = parse_script(src).unwrap();
        assert_eq!(steps.len(), 5);
        assert_eq!(steps[0], Step::Send("hello".into()));
        assert_eq!(
            steps[1],
            Step::Expect { pattern: "login:".into(), timeout: Duration::from_secs(5) }
        );
        assert_eq!(steps[2], Step::SendRaw(vec![0xde, 0xad]));
        assert_eq!(steps[3], Step::Delay(Duration::from_millis(100)));
        assert_eq!(steps[4], Step::Log("done".into()));
    }

    #[test]
    fn unescape_and_default_timeout() {
        let steps = parse_script("send a\\r\\nb\nexpect =>").unwrap();
        assert_eq!(steps[0], Step::Send("a\r\nb".into()));
        assert_eq!(
            steps[1],
            Step::Expect { pattern: "=>".into(), timeout: Duration::from_secs(10) }
        );
    }

    #[test]
    fn parse_errors() {
        assert!(parse_script("frobnicate x").is_err());
        assert!(parse_script("sendraw xyz").is_err());
        assert!(parse_script("delay abc").is_err());
        assert!(parse_script("expect").is_err());
    }
}
