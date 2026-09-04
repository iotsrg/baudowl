//! Firmware extraction over UART.
//!
//! From a U-Boot prompt this drives `sf read`/`nand read`/`mmc read` into RAM
//! then `md.b` to stream the bytes out, parses the hex, and reconstructs a
//! binary image. From a root shell it pulls a file with `base64` and decodes
//! it. All transport is plain text over the serial line, no extra protocol.

use std::error::Error;
use std::fs::File;
use std::io::Write as IoWrite;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use colored::*;

use crate::ui;
use crate::session::Session;

/// Storage backend a dump reads from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlashSource {
    Sf,
    Nand,
    Mmc,
    Ram,
}

impl FlashSource {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "sf" | "spi" => Some(Self::Sf),
            "nand" => Some(Self::Nand),
            "mmc" | "emmc" => Some(Self::Mmc),
            "ram" | "mem" => Some(Self::Ram),
            _ => None,
        }
    }

    /// U-Boot command that loads `len` bytes at flash `off` into RAM `ram`.
    /// `mmc` uses 512-byte block addressing, so byte values are converted.
    fn read_cmd(&self, ram: u64, off: u64, len: u64) -> Option<String> {
        match self {
            Self::Sf => Some(format!("sf read {:#x} {:#x} {:#x}", ram, off, len)),
            Self::Nand => Some(format!("nand read {:#x} {:#x} {:#x}", ram, off, len)),
            // len rounded up to whole 512-byte blocks. Written as div-then-adjust
            // (not `div_ceil`, which needs Rust 1.73) and overflow-free.
            Self::Mmc => Some(format!(
                "mmc read {:#x} {:#x} {:#x}",
                ram,
                off / 0x200,
                len / 0x200 + u64::from(len % 0x200 != 0)
            )),
            Self::Ram => None,
        }
    }
}

/// Parse U-Boot `md.b` output into raw bytes. Data lines look like:
///   `83f00000: 27 05 19 56 0c 2e 2f 30 ...    'W../0`
/// The hex column is taken up to the run of 2+ spaces that precedes the ASCII
/// gutter. Lines without a hex `address:` prefix (command echo, prompt) are
/// skipped, so a full transcript can be passed in directly.
pub fn parse_md_b(output: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for line in output.lines() {
        let line = line.trim_end_matches('\r');
        let colon = match line.find(':') {
            Some(c) => c,
            None => continue,
        };
        let addr = line[..colon].trim();
        if addr.is_empty() || !addr.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let rest = &line[colon + 1..];
        let hex_section = match rest.find("  ") {
            Some(i) => &rest[..i],
            None => rest,
        };
        for tok in hex_section.split_whitespace() {
            if tok.len() == 2 {
                if let Ok(b) = u8::from_str_radix(tok, 16) {
                    bytes.push(b);
                }
            }
        }
    }
    bytes
}

/// Decode standard base64 (lenient: skips whitespace and any non-alphabet
/// byte, stops at padding). Used on a marker-delimited region, so stray
/// console text outside the markers never reaches here.
pub fn decode_base64(input: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for c in input.bytes() {
        let val: u8 = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => continue,
        };
        acc = (acc << 6) | val as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    out
}

/// Text between the LAST `start` marker and the next `end` after it. Using the
/// last start skips the marker copy that appears in the echoed command line.
fn extract_last<'a>(haystack: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let s = haystack.rfind(start)? + start.len();
    let e = haystack[s..].find(end)? + s;
    Some(&haystack[s..e])
}

/// Estimate how long `len` bytes of `md.b` output takes at `baud`, with margin.
fn dump_window(len: u64, baud: u32) -> Duration {
    // md.b prints roughly 4 chars/byte plus ~14 chars of address/ascii per line.
    // Saturating throughout: `len` comes straight from --dump-length, so a huge
    // value would otherwise overflow (debug panic, or a silently wrapped and
    // far-too-short timeout in release). The result is clamped to 120s anyway.
    let chars = len
        .saturating_mul(4)
        .saturating_add((len / 16).saturating_add(1).saturating_mul(14));
    let bytes_per_sec = (baud / 10).max(1) as u64;
    let secs = (chars / bytes_per_sec).saturating_add(3);
    Duration::from_secs(secs.clamp(3, 120))
}

/// Send a command and return everything the device emitted until `prompt`
/// reappears (or `timeout`), using the full transcript so large dumps are not
/// truncated by the matcher's sliding window.
fn run_capture(s: &mut Session, cmd: &str, prompt: &str, timeout: Duration) -> String {
    s.start_capture();
    let _ = s.send_line(cmd);
    s.expect(&[prompt.to_string()], timeout);
    String::from_utf8_lossy(&s.log).into_owned()
}

/// Read `len` bytes of device memory at `addr` via `md.b`.
pub fn read_mem(s: &mut Session, addr: u64, len: u64, prompt: &str, baud: u32) -> Vec<u8> {
    let text = run_capture(
        s,
        &format!("md.b {:#x} {:#x}", addr, len),
        prompt,
        dump_window(len, baud),
    );
    parse_md_b(&text)
}

/// Write `value` (one byte) `count` times at `addr` via `mw.b`.
pub fn write_mem(s: &mut Session, addr: u64, value: u8, count: u64, prompt: &str) {
    let _ = run_capture(
        s,
        &format!("mw.b {:#x} {:#x} {:#x}", addr, value, count.max(1)),
        prompt,
        Duration::from_secs(3),
    );
}

/// Break into U-Boot, confirm the console responds, then write a byte to
/// memory (a memory-patch primitive: e.g. neuter a check before `bootm`).
#[allow(clippy::too_many_arguments)]
pub fn write_flow(
    port: &str,
    baud: u32,
    addr: u64,
    value: u8,
    count: u64,
    interrupt_key: &[u8],
    break_timeout: Duration,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    println!("\n{}", "=== U-BOOT MEMORY WRITE ===".bold().magenta());
    println!(
        "{} {} @ {} baud  mw.b {:#x} = {:#x} x{}",
        "Target:".cyan(),
        port,
        baud,
        addr,
        value,
        count
    );
    let mut s = Session::open(port, baud, running)?;
    s.echo = true;
    if break_in(&mut s, interrupt_key, &[], break_timeout).is_none() {
        return Err("no bootloader prompt reached".into());
    }
    s.send_line("")?;
    if s
        .expect(&crate::autoroot::default_prompts(), Duration::from_secs(2))
        .is_none()
    {
        return Err("console did not respond; aborting before write".into());
    }
    write_mem(&mut s, addr, value, count, "=> ");
    println!(
        "\n{} wrote {:#x} ({} byte(s)) at {:#x}",
        "[+]".bold().green(),
        value,
        count,
        addr
    );
    Ok(())
}

/// Options for a flash/RAM dump.
pub struct DumpOpts {
    pub source: FlashSource,
    pub ram_addr: u64,
    pub offset: u64,
    pub length: u64,
    pub chunk: u64,
    pub out_path: String,
    pub interrupt_key: Vec<u8>,
    pub break_timeout: Duration,
    pub prompt: Option<String>,
    /// Pre-fill the RAM staging window with 0xFF before each flash read, so any
    /// bytes a short read leaves untouched show up as 0xFF instead of stale RAM.
    pub prefill: bool,
}

/// U-Boot command that fills `len` bytes at `ram` with 0xFF. Sent before a
/// flash read so a short/failed read is visible as a run of 0xFF in the image
/// rather than leftover RAM contents.
fn prefill_cmd(ram: u64, len: u64) -> String {
    format!("mw.b {:#x} 0xff {:#x}", ram, len)
}

fn break_in(s: &mut Session, key: &[u8], extra: &[String], timeout: Duration) -> Option<String> {
    let mut prompts = crate::autoroot::default_prompts();
    prompts.extend_from_slice(extra);
    s.spam_until(key, &prompts, timeout, Duration::from_millis(80))
        .map(|(_, w)| w)
}

/// Dump flash or RAM to a file. Breaks into U-Boot first, confirms the console
/// responds, then loops `read into RAM -> md.b -> parse -> append`.
pub fn dump(
    port: &str,
    baud: u32,
    opts: &DumpOpts,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    println!("\n{}", "=== FIRMWARE DUMP (U-Boot) ===".bold().magenta());
    println!(
        "{} {} @ {} baud  source={:?} len={:#x} -> {}",
        "Target:".cyan(),
        port,
        baud,
        opts.source,
        opts.length,
        opts.out_path
    );
    let mut s = Session::open(port, baud, running.clone())?;
    s.echo = true;

    let extra: Vec<String> = opts.prompt.iter().cloned().collect();
    println!(
        "{} Power-cycle the target now. Interrupting autoboot for {}s...",
        "[*]".bold().yellow(),
        opts.break_timeout.as_secs()
    );
    let win = break_in(&mut s, &opts.interrupt_key, &extra, opts.break_timeout);
    if win.is_none() {
        return Err("no bootloader prompt reached; wrong baud, not U-Boot, or window missed".into());
    }
    let prompt = opts
        .prompt
        .clone()
        .unwrap_or_else(|| "=> ".to_string());
    s.send_line("")?;
    if s.expect(&crate::autoroot::default_prompts(), Duration::from_secs(2)).is_none() {
        return Err("console did not echo the prompt back; aborting before dump".into());
    }
    println!("\n{} Prompt reached, starting dump...", "[*]".bold().green());
    if opts.prefill && opts.source != FlashSource::Ram {
        println!("{} pre-filling RAM with 0xFF before each read", "[*]".cyan());
    }

    let mut file = File::create(&opts.out_path)?;
    let mut done: u64 = 0;
    let chunk = opts.chunk.max(0x40);
    while done < opts.length {
        if !running.load(Ordering::SeqCst) {
            println!("{}", "interrupted".yellow());
            break;
        }
        let this = chunk.min(opts.length - done);
        // Saturating: offset comes from --dump-mem/--dump-offset and may sit
        // near u64::MAX, where `offset + done` would overflow.
        let cur_offset = opts.offset.saturating_add(done);
        let md_addr = if opts.source == FlashSource::Ram {
            // Reading device RAM directly: pre-fill would destroy the target
            // data, so it is only ever applied to the flash-staging path below.
            cur_offset
        } else {
            if opts.prefill {
                let _ = run_capture(
                    &mut s,
                    &prefill_cmd(opts.ram_addr, this),
                    &prompt,
                    Duration::from_secs(8),
                );
            }
            let cmd = opts
                .source
                .read_cmd(opts.ram_addr, cur_offset, this)
                .ok_or("source has no read command")?;
            let _ = run_capture(&mut s, &cmd, &prompt, Duration::from_secs(8));
            opts.ram_addr
        };
        let bytes = read_mem(&mut s, md_addr, this, &prompt, baud);
        if bytes.is_empty() {
            return Err(format!(
                "no data parsed at offset {:#x}; md.b may be unsupported or prompt mismatched",
                cur_offset
            )
            .into());
        }
        file.write_all(&bytes)?;
        // bytes is non-empty (checked above), so `done` always advances and the
        // loop cannot spin forever.
        done = done.saturating_add(bytes.len() as u64);
        print!(
            "\r{} {:#x}/{:#x} ({:.0}%)   ",
            "dumped".green(),
            done,
            opts.length,
            done as f64 / opts.length as f64 * 100.0
        );
        std::io::stdout().flush().ok();
    }
    file.flush()?;
    ui::win(
        "FIRMWARE EXTRACTED",
        &format!("{} bytes -> {}", done, opts.out_path),
    );
    Ok(())
}

/// Options for a TFTP-based dump (fast path for boards with U-Boot networking).
pub struct TftpOpts {
    pub source: FlashSource,
    pub ram_addr: u64,
    pub offset: u64,
    pub length: u64,
    pub out_path: String,
    /// This host's IP on the device network; the target uploads to it.
    pub server_ip: String,
    /// Device IP for `setenv ipaddr`; skip when the device already has one.
    pub device_ip: Option<String>,
    /// Address baudowl's TFTP server binds (port 69 needs privilege).
    pub bind: String,
    /// Filename U-Boot names in `tftpput` (cosmetic; output goes to `out_path`).
    pub filename: String,
    pub interrupt_key: Vec<u8>,
    pub break_timeout: Duration,
    pub prompt: Option<String>,
}

/// Dump flash/RAM by staging it into RAM in U-Boot and having the board push it
/// to a TFTP server that baudowl runs itself. Orders of magnitude faster than
/// `md.b` over serial, but needs U-Boot built with networking and `tftpput`,
/// and the host reachable from the device over Ethernet.
pub fn tftp_dump(
    port: &str,
    baud: u32,
    opts: &TftpOpts,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    println!("\n{}", "=== FIRMWARE DUMP (U-Boot TFTP) ===".bold().magenta());
    println!(
        "{} {} @ {} baud  source={:?} len={:#x} -> {} (via {})",
        "Target:".cyan(),
        port,
        baud,
        opts.source,
        opts.length,
        opts.out_path,
        opts.server_ip
    );

    // Bind the receiver before touching the board, so the WRQ can never arrive
    // before we are listening.
    let sock = UdpSocket::bind(&opts.bind).map_err(|e| -> Box<dyn Error> {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!(
                "cannot bind TFTP server on {} (port 69 is privileged: run with sudo, \
                 or grant it with `sudo setcap cap_net_bind_service=+ep $(command -v baudowl)`): {}",
                opts.bind, e
            )
            .into()
        } else {
            format!("cannot bind TFTP server on {}: {}", opts.bind, e).into()
        }
    })?;
    println!("{} TFTP server listening on {}", "[*]".cyan(), opts.bind);

    let mut s = Session::open(port, baud, running.clone())?;
    s.echo = true;

    let extra: Vec<String> = opts.prompt.iter().cloned().collect();
    println!(
        "{} Power-cycle the target now. Interrupting autoboot for {}s...",
        "[*]".bold().yellow(),
        opts.break_timeout.as_secs()
    );
    if break_in(&mut s, &opts.interrupt_key, &extra, opts.break_timeout).is_none() {
        return Err("no bootloader prompt reached; wrong baud, not U-Boot, or window missed".into());
    }
    let prompt = opts.prompt.clone().unwrap_or_else(|| "=> ".to_string());
    s.send_line("")?;
    if s
        .expect(&crate::autoroot::default_prompts(), Duration::from_secs(2))
        .is_none()
    {
        return Err("console did not echo the prompt back; aborting".into());
    }

    // Network environment.
    if let Some(dip) = &opts.device_ip {
        let _ = run_capture(&mut s, &format!("setenv ipaddr {}", dip), &prompt, Duration::from_secs(3));
    }
    let _ = run_capture(
        &mut s,
        &format!("setenv serverip {}", opts.server_ip),
        &prompt,
        Duration::from_secs(3),
    );

    // Stage the region into RAM (skipped when dumping RAM directly).
    let src_addr = if opts.source == FlashSource::Ram {
        opts.offset
    } else {
        match opts.source {
            FlashSource::Sf => {
                let _ = run_capture(&mut s, "sf probe 0", &prompt, Duration::from_secs(5));
            }
            FlashSource::Mmc => {
                let _ = run_capture(&mut s, "mmc dev 0", &prompt, Duration::from_secs(5));
            }
            _ => {}
        }
        let cmd = opts
            .source
            .read_cmd(opts.ram_addr, opts.offset, opts.length)
            .ok_or("source has no read command")?;
        println!("{} staging into RAM: {}", "[*]".cyan(), cmd);
        let _ = run_capture(&mut s, &cmd, &prompt, Duration::from_secs(90));
        opts.ram_addr
    };

    // Kick off the upload, then receive it.
    let put = format!(
        "tftpput {:#x} {:#x} {}:{}",
        src_addr, opts.length, opts.server_ip, opts.filename
    );
    println!("{} {}", "[*]".bold().yellow(), put);
    s.send_line(&put)?;

    let max = opts.length.saturating_add(0x1000);
    let received = crate::tftp::serve_wrq(
        &sock,
        &opts.out_path,
        &running,
        Duration::from_secs(45),
        Duration::from_secs(5),
        max,
    )
    .map_err(|e| -> Box<dyn Error> {
        format!(
            "TFTP receive failed: {} (does this U-Boot have tftpput and a reachable network?)",
            e
        )
        .into()
    })?;

    // Drain any trailing U-Boot status line for the operator.
    let _ = s.collect(Duration::from_secs(2));

    if received != opts.length {
        ui::warn(&format!(
            "received {} bytes, expected {:#x}; image may be short",
            received, opts.length
        ));
    }
    ui::win(
        "FIRMWARE EXTRACTED (TFTP)",
        &format!("{} bytes -> {}", received, opts.out_path),
    );
    Ok(())
}

/// Options for uploading a file into U-Boot RAM over serial.
pub struct LoadOpts {
    pub data: Vec<u8>,
    pub addr: u64,
    pub mode: crate::xfer::XferMode,
    pub filename: String,
    /// U-Boot command to run after the upload (e.g. "go 0x80000000", "bootm").
    pub go_after: Option<String>,
    pub interrupt_key: Vec<u8>,
    pub break_timeout: Duration,
    pub prompt: Option<String>,
}

/// Break into U-Boot and push a file into RAM with `loadx`/`loady`, then
/// optionally run a follow-up command. This is the serial ingress counterpart
/// to the md.b/TFTP egress paths: load a RAM dumper stub, a replacement image,
/// or a payload over the console alone, no network needed.
pub fn load_file(
    port: &str,
    baud: u32,
    opts: LoadOpts,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    println!("\n{}", "=== SERIAL LOAD (U-Boot) ===".bold().magenta());
    println!(
        "{} {} @ {} baud  {} bytes -> {:#x} via {:?}",
        "Target:".cyan(),
        port,
        baud,
        opts.data.len(),
        opts.addr,
        opts.mode
    );
    let mut s = Session::open(port, baud, running.clone())?;
    s.echo = true;

    let extra: Vec<String> = opts.prompt.iter().cloned().collect();
    println!(
        "{} Power-cycle the target now. Interrupting autoboot for {}s...",
        "[*]".bold().yellow(),
        opts.break_timeout.as_secs()
    );
    if break_in(&mut s, &opts.interrupt_key, &extra, opts.break_timeout).is_none() {
        return Err("no bootloader prompt reached; wrong baud, not U-Boot, or window missed".into());
    }
    s.send_line("")?;
    if s
        .expect(&crate::autoroot::default_prompts(), Duration::from_secs(2))
        .is_none()
    {
        return Err("console did not echo the prompt back; aborting".into());
    }

    // Put the device into receive mode, then run the sender. The device prints
    // a "## Ready for binary ... download" banner and then a C/NAK; the sender
    // waits for that start byte itself, so a brief settle is enough here.
    let recv_cmd = opts.mode.uboot_cmd(opts.addr);
    println!("{} {}", "[*]".bold().yellow(), recv_cmd);
    s.send_line(&recv_cmd)?;
    s.collect(Duration::from_millis(600));

    let sent = s
        .transfer_out(&opts.data, opts.mode, &opts.filename)
        .map_err(|e| -> Box<dyn Error> {
            format!("serial transfer failed: {} (does this U-Boot have loadx/loady?)", e).into()
        })?;

    // Resync on the prompt after the loader returns.
    s.expect(&crate::autoroot::default_prompts(), Duration::from_secs(5));
    ui::win(
        "PAYLOAD LOADED",
        &format!("{} bytes -> {:#x}", sent, opts.addr),
    );

    if let Some(cmd) = &opts.go_after {
        ui::danger("EXECUTING LOADED IMAGE", cmd);
        s.send_line(cmd)?;
        s.collect(Duration::from_secs(3));
    }
    Ok(())
}

/// Pull a file from an already-open root shell with `base64`, decode, and save.
/// Assumes the device is sitting at a shell prompt (for example after
/// `--autoroot`, or a console that is already logged in).
pub fn shell_dump(
    port: &str,
    baud: u32,
    remote_path: &str,
    out_path: &str,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    println!("\n{}", "=== SHELL DUMP (base64 over UART) ===".bold().magenta());
    println!("{} {} : {} -> {}", "Target:".cyan(), port, remote_path, out_path);
    let mut s = Session::open(port, baud, running)?;
    s.echo = true;
    s.send_line("")?;
    s.collect(Duration::from_millis(400));

    const START: &str = "__BAUDOWL_B64_START__";
    const END: &str = "__BAUDOWL_B64_END__";
    s.start_capture();
    // echo markers around base64 so the prompt and command echo never pollute
    // the decoded stream.
    s.send_line(&format!(
        "echo {start}; base64 {path} 2>/dev/null || base64 < {path}; echo {end}",
        start = START,
        end = END,
        path = remote_path
    ))?;
    if s.expect(&[END.to_string()], Duration::from_secs(120)).is_none() {
        return Err("end marker not seen; base64 missing on target, or file unreadable".into());
    }
    let text = String::from_utf8_lossy(&s.log).into_owned();
    let b64 = extract_last(&text, START, END)
        .ok_or("could not locate base64 markers in output")?;
    let data = decode_base64(b64);
    if data.is_empty() {
        return Err("decoded zero bytes; file may be empty or base64 failed".into());
    }
    std::fs::write(out_path, &data)?;
    ui::win(
        "FILE EXTRACTED",
        &format!("{} bytes -> {}", data.len(), out_path),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_md_b_basic() {
        let out = "md.b 83f00000 13\r\n\
                   83f00000: 27 05 19 56 0c 2e 2f 30 31 2e 31 28 4a 75 6c 20    'W../01.1(Jul \r\n\
                   83f00010: 31 32 29                                           12)\r\n\
                   => ";
        let b = parse_md_b(out);
        assert_eq!(&b[..4], &[0x27, 0x05, 0x19, 0x56]);
        assert_eq!(b.len(), 19);
        assert_eq!(&b[16..], &[0x31, 0x32, 0x29]);
    }

    #[test]
    fn parse_md_b_ignores_noise() {
        let out = "=> md.b 0 4\nversion\nbootargs=console=ttyS0\n0: de ad be ef   ....\n=> ";
        assert_eq!(parse_md_b(out), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn base64_roundtrip_vectors() {
        assert_eq!(decode_base64("aGVsbG8="), b"hello");
        assert_eq!(decode_base64("aGVsbG8gd29ybGQ="), b"hello world");
        // with newlines (coreutils wraps at 76 cols)
        assert_eq!(decode_base64("Zm9v\nYmFy\n"), b"foobar");
    }

    #[test]
    fn extract_last_marker() {
        // echoed command carries the markers first, the real payload second
        let t = "echo __S__; base64; echo __E__\n__S__\nPAYLOAD\n__E__\n# ";
        assert_eq!(extract_last(t, "__S__", "__E__"), Some("\nPAYLOAD\n"));
        assert_eq!(extract_last(t, "__S__", "__MISSING__"), None);
    }

    #[test]
    fn dump_window_survives_huge_length() {
        // `--dump-length 0xFFFFFFFFFFFFFFFF` reaches this with len = u64::MAX.
        // `len * 4` overflows: debug panics, release silently wraps to a bogus
        // (too short) timeout. Must saturate and clamp instead.
        let w = dump_window(u64::MAX, 115200);
        assert!(w.as_secs() <= 120 && w.as_secs() >= 3);
        assert_eq!(dump_window(0, 115200).as_secs(), 3);
        let _ = dump_window(u64::MAX, 1);
    }

    #[test]
    fn prefill_cmd_format() {
        assert_eq!(prefill_cmd(0x8000_0000, 0x1000), "mw.b 0x80000000 0xff 0x1000");
        assert_eq!(prefill_cmd(0x8200_0000, 0x40), "mw.b 0x82000000 0xff 0x40");
    }

    #[test]
    fn mmc_uses_block_addressing() {
        // 0x1000 bytes at offset 0x200 -> block 1, 8 blocks
        assert_eq!(
            FlashSource::Mmc.read_cmd(0x8000_0000, 0x200, 0x1000).unwrap(),
            "mmc read 0x80000000 0x1 0x8"
        );
        assert_eq!(
            FlashSource::Sf.read_cmd(0x8000_0000, 0x10000, 0x1000).unwrap(),
            "sf read 0x80000000 0x10000 0x1000"
        );
    }
}
