use std::{
    io::{self, Read, Write},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use clap::Parser;
use colored::*;

use std::path::{Path, PathBuf};

mod session;
mod autoroot;
mod uboot;
mod framing;
mod script;
mod recon;
mod reset;
mod glitch;
mod sigrok;
mod timing;
mod fuzz;
mod sniff;
mod mitm;
mod ports;
mod ui;

/// Validate config name contains only safe characters (alphanumeric, dash, underscore)
fn validate_config_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Config name cannot be empty".to_string());
    }
    if name.len() > 64 {
        return Err("Config name too long (max 64 chars)".to_string());
    }
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err("Config name can only contain alphanumeric characters, dashes, and underscores".to_string());
    }
    Ok(())
}

/// Validate serial port path is a valid device path
fn validate_port_path(port: &str) -> Result<(), String> {
    // Must start with /dev/
    if !port.starts_with("/dev/") {
        return Err("Port must be a device path starting with /dev/".to_string());
    }
    // No path traversal
    if port.contains("..") {
        return Err("Port path cannot contain '..'".to_string());
    }
    // No newlines or control characters (prevents config injection)
    if port.chars().any(|c| c.is_control()) {
        return Err("Port path cannot contain control characters".to_string());
    }
    // Validate it looks like a real device path
    let path = Path::new(port);
    if path.components().count() > 4 {
        return Err("Port path too deep".to_string());
    }
    Ok(())
}

/// System-wide minicom profile path. `minicom <name>` reads this directly.
fn system_minicom_path(name: &str) -> PathBuf {
    PathBuf::from(format!("/etc/minicom/minirc.{}", name))
}

/// Per-user minicom profile path. `minicom <name>` also reads
/// `$HOME/.minirc.<name>`, so this works as a fallback when the system path is
/// not writable.
fn user_minicom_path(home: &Path, name: &str) -> PathBuf {
    home.join(format!(".minirc.{}", name))
}

/// Resolve the user's home directory from `$HOME` (unset or empty -> None).
fn home_dir() -> Option<PathBuf> {
    match std::env::var_os("HOME") {
        Some(h) if !h.is_empty() => Some(PathBuf::from(h)),
        _ => None,
    }
}

/// Whether a failed write to the system path should trigger the user-dir
/// fallback (no permission, or a missing path we could not create) rather than
/// being treated as a hard error.
fn should_fall_back(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
    )
}

/// Write `contents` to `path`, creating the parent directory if it is missing.
fn write_config_to(path: &Path, contents: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)
}

/// Parse a hex byte string ("deadbeef" or "de ad be ef") into bytes.
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    // Operate on bytes, not str slices: `s` comes from the command line and may
    // contain multibyte UTF-8, which would make a byte-indexed str slice panic
    // mid-codepoint. Non-ASCII bytes simply fail to_digit here.
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if (clean.len() & 1) != 0 {
        return Err(format!("hex '{}' must be even length", s));
    }
    clean
        .chunks(2)
        .map(|pair| {
            match (
                (pair[0] as char).to_digit(16),
                (pair[1] as char).to_digit(16),
            ) {
                (Some(hi), Some(lo)) => Ok(((hi << 4) | lo) as u8),
                _ => Err(format!("bad hex in '{}'", s)),
            }
        })
        .collect()
}

/// Parse MITM rule specs of the form DIR:findhex:replacehex.
fn parse_mitm_rules(specs: &[String]) -> Result<Vec<mitm::Rule>, String> {
    let mut rules = Vec::new();
    for spec in specs {
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() != 3 {
            return Err(format!("rule '{}' must be DIR:findhex:replacehex", spec));
        }
        let dir = match parts[0].to_ascii_lowercase().as_str() {
            "a2b" => mitm::Dir::AtoB,
            "b2a" => mitm::Dir::BtoA,
            "both" => mitm::Dir::Both,
            other => return Err(format!("bad direction '{}' (a2b|b2a|both)", other)),
        };
        let find = parse_hex_bytes(parts[1])?;
        if find.is_empty() {
            return Err(format!("rule '{}' has an empty find pattern", spec));
        }
        rules.push(mitm::Rule {
            dir,
            find,
            replace: parse_hex_bytes(parts[2])?,
        });
    }
    Ok(rules)
}

/// Parse a number that may be hex (0x...) or decimal.
fn parse_num(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).map_err(|_| format!("invalid hex number '{}'", s))
    } else {
        s.parse::<u64>().map_err(|_| format!("invalid number '{}'", s))
    }
}

/// Read up to ~1 KB from the port for `dur`, for protocol fingerprinting.
fn sample_bytes(port: &str, baud: u32, dur: Duration, running: Arc<AtomicBool>) -> Vec<u8> {
    let mut data = Vec::new();
    if let Ok(mut p) = serialport::new(port, baud)
        .timeout(Duration::from_millis(100))
        .open()
    {
        p.clear(serialport::ClearBuffer::All).ok();
        let deadline = Instant::now() + dur;
        let mut buf = [0u8; 256];
        while Instant::now() < deadline && running.load(Ordering::SeqCst) && data.len() < 1024 {
            if let Ok(n) = p.read(&mut buf) {
                data.extend_from_slice(&buf[..n]);
            }
        }
    }
    data
}

/// Score how likely `data` is a correct-baud ASCII console stream, 0-100.
///
/// The weights come from measurement, not intuition. A UART sampling at the
/// wrong rate produces bytes with the high bit set very often (misaligned
/// sampling drags start/stop bits into the data field): on a simulated U-Boot
/// banner the correct rate yields 0% high-bit bytes while every wrong rate
/// yields 36-47%. That single feature separates far better than anything else,
/// so it carries real weight here.
///
/// Shannon entropy was evaluated and deliberately left out: on the same corpus
/// the correct rate scored 4.73 bits/byte while wrong rates spanned 3.66-5.41,
/// so it overlaps the true signal and would add noise rather than separation.
///
/// Scope: this targets ASCII console output. A correct-baud binary protocol
/// (Modbus, MAVLink) legitimately scores low here; use --detect-protocol for
/// those.
fn readability_score(data: &[u8]) -> u32 {
    if data.is_empty() {
        return 0;
    }
    let total = data.len() as f32;
    let mut printable = 0u32; // includes tab/CR/LF, which real consoles emit
    let mut alnum = 0u32;
    let mut structure = 0u32; // whitespace and common punctuation
    let mut high_bit = 0u32; // >0x7F: the wrong-baud signature
    let mut null_ff = 0u32; // 0x00/0xFF: framing errors and idle-line breaks

    for &b in data {
        if (0x20..=0x7e).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r') {
            printable += 1;
        }
        if b.is_ascii_alphanumeric() {
            alnum += 1;
        }
        if matches!(
            b,
            b' ' | b'\n' | b'\r' | b'\t' | b'.' | b':' | b'-' | b'=' | b'[' | b']' | b'/' | b','
        ) {
            structure += 1;
        }
        if b > 0x7f {
            high_bit += 1;
        }
        if b == 0x00 || b == 0xff {
            null_ff += 1;
        }
    }

    let printable_ratio = printable as f32 / total;
    let alnum_ratio = alnum as f32 / total;
    // Structure saturates: 25% whitespace/punctuation is already prose-like,
    // more than that should not keep adding confidence.
    let structure_ratio = (structure as f32 / total / 0.25).min(1.0);
    let high_bit_ratio = high_bit as f32 / total;
    let null_ff_ratio = null_ff as f32 / total;

    let text = 45.0 * printable_ratio + 25.0 * alnum_ratio + 15.0 * structure_ratio;
    let framing = 15.0 * (1.0 - high_bit_ratio);
    let score = text + framing - 40.0 * null_ff_ratio;
    score.clamp(0.0, 100.0) as u32
}

const BANNER: &str = r#"
    )___(
    (o o)   BAUDOWL v1.7.0
   /  V  \  -------------------
  /(     )\  The Serial Port Detective
    ^^ ^^   Sniffs out baudrates in seconds!
"#;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "baudowl - The Ultimate Serial Port Detective",
    long_about = None,
    after_help = "Examples:\n  baudowl -p /dev/ttyACM0 --highspeed\n  baudowl --turbo -q\n  baudowl -n myconfig --auto\n  baudowl --baud 115200 --autoroot --dry-run"
)]
struct Args {
    /// Specify serial port to use
    #[arg(short, long, default_value = "/dev/ttyUSB0")]
    port: String,

    /// Set timeout period (seconds) in auto-detect mode
    #[arg(short, long, default_value_t = 5)]
    timeout: u64,

    /// Minimum readability score (0-100) required to accept a baudrate
    #[arg(short = 'c', long, default_value_t = 60)]
    threshold: usize,

    /// Save config as <name> and invoke Minicom (implies --auto)
    #[arg(short, long)]
    name: Option<String>,

    /// Enable auto-detect mode
    #[arg(short, long)]
    auto: bool,

    /// Display supported baud rates and exit
    #[arg(short, long)]
    baudlist: bool,

    /// List available serial ports with USB info and exit
    #[arg(long)]
    list: bool,

    /// With --list, also show legacy PCI/unknown ports (ttyS*)
    #[arg(long)]
    list_all: bool,

    /// Disable coloured output (also honours the NO_COLOR env var)
    #[arg(long)]
    no_color: bool,

    /// After detecting the baudrate, stay connected and stream live output
    /// (read-only, Ctrl-C to exit)
    #[arg(short = 'm', long)]
    monitor: bool,

    /// Like --monitor but two-way: type commands to the device (Ctrl-C exits)
    #[arg(short = 'i', long)]
    interactive: bool,

    /// With --monitor, pass bytes through untranslated instead of masking
    /// non-printable ones
    #[arg(long)]
    monitor_raw: bool,

    /// Suppress data display (quiet mode)
    #[arg(short, long)]
    quiet: bool,

    /// Enable turbo mode (faster detection)
    #[arg(long)]
    turbo: bool,

    /// Enable ultra-high baudrates (1Mbps+)
    #[arg(long)]
    highspeed: bool,

    /// Force a specific baudrate and skip auto-detection (e.g. --baud 115200)
    #[arg(long)]
    baud: Option<u32>,

    /// Break into U-Boot, inject shell bootargs, and drop to a root shell
    #[arg(long)]
    autoroot: bool,

    /// Boot argument or preset name to obtain a shell (see --list-shell-args)
    #[arg(long, default_value = "init=/bin/sh")]
    shell_arg: String,

    /// Key spammed to interrupt autoboot: enter|space|ctrl-c|esc|\xNN
    #[arg(long, default_value = "enter")]
    interrupt_key: String,

    /// Seconds to spam the interrupt key while waiting for a bootloader prompt
    #[arg(long, default_value_t = 30)]
    break_timeout: u64,

    /// Also append the 'single' (single-user) boot flag
    #[arg(long)]
    single: bool,

    /// U-Boot command used to continue booting after setenv
    #[arg(long, default_value = "boot")]
    boot_cmd: String,

    /// Persist the modified env to flash with saveenv (DANGEROUS, default off)
    #[arg(long)]
    persist: bool,

    /// Show the exact commands that would be sent, but do not modify or boot
    #[arg(long)]
    dry_run: bool,

    /// List the built-in shell boot-argument presets and exit
    #[arg(long)]
    list_shell_args: bool,

    // --- Firmware extraction (U-Boot / shell) ---
    /// Dump flash to a file over U-Boot (needs --dump-out, --dump-length)
    #[arg(long)]
    dump_flash: bool,

    /// Dump device memory at this hex address over U-Boot md (needs --dump-length)
    #[arg(long, value_name = "HEXADDR")]
    dump_mem: Option<String>,

    /// Flash source for --dump-flash: sf|nand|mmc
    #[arg(long, default_value = "sf")]
    dump_source: String,

    /// Staging RAM address for flash reads (hex)
    #[arg(long, default_value = "0x80000000")]
    dump_ram_addr: String,

    /// Flash byte offset to start dumping (hex or decimal)
    #[arg(long, default_value = "0x0")]
    dump_offset: String,

    /// Number of bytes to dump (hex or decimal)
    #[arg(long, default_value = "0x10000")]
    dump_length: String,

    /// Bytes per md.b chunk (hex or decimal)
    #[arg(long, default_value = "0x1000")]
    dump_chunk: String,

    /// Output file for dumps and harvest transcripts
    #[arg(long, default_value = "dump.bin")]
    dump_out: String,

    /// Pull a file from an open root shell via base64 (give the remote path)
    #[arg(long, value_name = "PATH")]
    shell_dump: Option<String>,

    /// Write a byte to device memory over U-Boot mw.b (give a hex address)
    #[arg(long, value_name = "HEXADDR")]
    write_mem: Option<String>,

    /// Byte value for --write-mem (hex or decimal)
    #[arg(long, default_value = "0x0")]
    write_value: String,

    /// Repeat count for --write-mem
    #[arg(long, default_value = "1")]
    write_count: String,

    // --- Detection ---
    /// Try framing combinations (8N1/7E1/...) and report the most readable
    #[arg(long)]
    detect_framing: bool,

    /// Sample the line and fingerprint a binary protocol (Modbus/NMEA/MAVLink)
    #[arg(long)]
    detect_protocol: bool,

    // --- Automation ---
    /// Run an expect-style script file over the serial line
    #[arg(long, value_name = "FILE")]
    script: Option<String>,

    /// Try default console credentials at a login: prompt
    #[arg(long)]
    cred_brute: bool,

    /// Harvest secrets from an open root shell (transcript to --dump-out)
    #[arg(long)]
    harvest: bool,

    // --- Hardware triggering ---
    /// Pulse a hardware reset over control lines: dtr|rts|esp
    #[arg(long, value_name = "PROFILE")]
    reset: Option<String>,

    /// Assert a serial BREAK (Unix) for --break-ms milliseconds
    #[arg(long)]
    send_break: bool,

    /// BREAK duration in milliseconds
    #[arg(long, default_value_t = 250)]
    break_ms: u64,

    /// Watch for this pattern and fire a glitch trigger when it appears
    #[arg(long, value_name = "PATTERN")]
    glitch_on: Option<String>,

    /// Trigger line for --glitch-on: rts|dtr|none
    #[arg(long, default_value = "rts")]
    glitch_line: String,

    /// Glitch trigger pulse width in microseconds
    #[arg(long, default_value_t = 200)]
    glitch_pulse_us: u64,

    /// External command to run when the glitch pattern hits
    #[arg(long)]
    glitch_cmd: Option<String>,

    /// Seconds to watch for the glitch pattern
    #[arg(long, default_value_t = 60)]
    glitch_timeout: u64,

    // --- Logic-analyzer baud detection ---
    /// Detect baud with a sigrok-cli analyzer (driver, e.g. fx2lafw)
    #[arg(long, value_name = "DRIVER")]
    sigrok_driver: Option<String>,

    /// sigrok capture sample rate (Hz)
    #[arg(long, default_value_t = 8_000_000)]
    sigrok_samplerate: u64,

    /// sigrok number of samples to capture
    #[arg(long, default_value_t = 1_000_000)]
    sigrok_samples: u64,

    /// sigrok channel carrying RX
    #[arg(long, default_value = "D0")]
    sigrok_channel: String,

    // --- Timing side-channel ---
    /// Recover a secret char-by-char by timing a non-constant-time console check
    #[arg(long)]
    timing_attack: bool,

    /// Character set to try per position
    #[arg(long, default_value = "abcdefghijklmnopqrstuvwxyz0123456789")]
    timing_charset: String,

    /// Maximum secret length to recover
    #[arg(long, default_value_t = 16)]
    timing_maxlen: usize,

    /// Timing samples per candidate character
    #[arg(long, default_value_t = 20)]
    timing_samples: usize,

    /// Response marker to time against (e.g. the rejection message)
    #[arg(long, default_value = "incorrect")]
    timing_marker: String,

    /// Text sent before each guess (to navigate to the input)
    #[arg(long, default_value = "")]
    timing_prefix: String,

    /// Outlier separation threshold (sigmas) to accept a character
    #[arg(long, default_value_t = 3.5)]
    timing_z: f64,

    /// Settle time between timing samples (ms)
    #[arg(long, default_value_t = 20)]
    timing_settle_ms: u64,

    /// TVLA-lite leakage test between --timing-class-a and --timing-class-b
    #[arg(long)]
    leakage_test: bool,

    /// Input class A for --leakage-test
    #[arg(long, default_value = "")]
    timing_class_a: String,

    /// Input class B for --leakage-test
    #[arg(long, default_value = "")]
    timing_class_b: String,

    // --- Serial fuzzer ---
    /// Fuzz a console/parser, detect crashes, auto-reset, and minimize the repro
    #[arg(long)]
    fuzz: bool,

    /// Seed input to mutate (text). Omit for fully random cases
    #[arg(long)]
    fuzz_seed_input: Option<String>,

    /// Maximum fuzz case length
    #[arg(long, default_value_t = 64)]
    fuzz_maxlen: usize,

    /// Number of fuzz iterations
    #[arg(long, default_value_t = 200)]
    fuzz_iterations: usize,

    /// Per-case response window (ms)
    #[arg(long, default_value_t = 800)]
    fuzz_timeout_ms: u64,

    /// Reset method between/after crashes: dtr|rts|cmd|none
    #[arg(long, default_value = "dtr")]
    fuzz_reset: String,

    /// Command to send for --fuzz-reset cmd
    #[arg(long)]
    fuzz_reset_cmd: Option<String>,

    /// PRNG seed for reproducible fuzzing
    #[arg(long, default_value_t = 1)]
    fuzz_seed: u64,

    /// Do not append CR after each fuzz case
    #[arg(long)]
    fuzz_no_newline: bool,

    /// Extra crash signature(s) to match (repeatable)
    #[arg(long)]
    fuzz_crash_sig: Vec<String>,

    /// Protocol-aware fuzzing: raw|modbus|nmea
    #[arg(long, default_value = "raw")]
    fuzz_protocol: String,

    // --- Passive sniff / replay / MITM ---
    /// Passively capture the line (read-only), timestamped
    #[arg(long)]
    sniff: bool,

    /// Save the raw sniff capture to this file
    #[arg(long, value_name = "FILE")]
    sniff_out: Option<String>,

    /// Fingerprint the protocol of the sniffed capture
    #[arg(long)]
    sniff_decode: bool,

    /// Idle gap (us) that separates frames in the sniff view
    #[arg(long, default_value_t = 5000)]
    sniff_idle_us: u64,

    /// Stop sniffing after this many bytes
    #[arg(long, default_value_t = 65536)]
    sniff_max: usize,

    /// Pulse a reset (dtr|rts|esp) right after opening, to capture boot output
    #[arg(long, value_name = "PROFILE")]
    sniff_reset: Option<String>,

    /// Replay the bytes of a file out the port
    #[arg(long, value_name = "FILE")]
    replay: Option<String>,

    /// Replay chunk size
    #[arg(long, default_value_t = 64)]
    replay_chunk: usize,

    /// Delay between replay chunks (ms)
    #[arg(long, default_value_t = 10)]
    replay_delay_ms: u64,

    /// Man-in-the-middle bridge between --port (A) and --mitm-port-b (B)
    #[arg(long)]
    mitm: bool,

    /// Second port for --mitm (the host side)
    #[arg(long, value_name = "PORT")]
    mitm_port_b: Option<String>,

    /// MITM rewrite rule DIR:findhex:replacehex (DIR = a2b|b2a|both), repeatable
    #[arg(long, value_name = "RULE")]
    mitm_rule: Vec<String>,
}

struct BaudOwl {
    args: Args,
    running: Arc<AtomicBool>,
    stats: DetectionStats,
}

#[derive(Default)]
struct DetectionStats {
    bytes_processed: usize,
    baudrates_tried: usize,
    detection_time: Duration,
}

impl BaudOwl {
    fn new(args: Args) -> Result<Self, String> {
        // Validate inputs before proceeding
        validate_port_path(&args.port)?;
        if let Some(ref name) = args.name {
            validate_config_name(name)?;
        }

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");

        let auto = args.auto || args.name.is_some();

        Ok(Self {
            args: Args { auto, ..args },
            running,
            stats: DetectionStats::default(),
        })
    }

    fn get_active_baudrates(&self) -> Vec<u32> {
        // Prioritize common baud rates first (most likely to hit)
        let mut common_rates = vec![
            115200, 9600, 57600, 38400, 19200, 230400, 460800, 921600,
            1200, 2400, 4800, 14400, 28800, 76800, 128000, 256000,
        ];
        
        if self.args.highspeed {
            common_rates.extend([1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000]);
        }

        if self.args.turbo {
            // Turbo mode: only most common rates
            vec![115200, 9600, 57600, 38400, 19200, 230400, 460800, 921600]
        } else {
            common_rates
        }
    }

    fn print_baudrates(&self) {
        let rates = self.get_active_baudrates();
        println!("{}", "Supported baudrates:".bold().green());
        for (i, rate) in rates.iter().enumerate() {
            print!("{:>8}", rate);
            if (i + 1) % 6 == 0 { println!(); }
        }
        println!();
    }

    fn detect_baudrate(&mut self) -> Result<u32, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let rates = self.get_active_baudrates();
        let mut best_baud: Option<u32> = None;
        let mut best_score: u32 = 0;
        let mut ranked: Vec<(u32, u32)> = Vec::new();

        println!("{}", "Starting detection...".bright_blue());
        if self.args.highspeed {
            println!("{}", "High-speed mode: Enabled".bright_magenta());
        }
        println!("Testing {} baud rates...\n", rates.len());

        for &baudrate in &rates {
            if !self.running.load(Ordering::SeqCst) {
                break;
            }

            self.stats.baudrates_tried += 1;
            print!("{} {:>7} baud... ", "Testing:".cyan(), baudrate);
            io::stdout().flush().ok();

            // Open port with short timeout for non-blocking behavior
            let port_result = serialport::new(&self.args.port, baudrate)
                .timeout(Duration::from_millis(100))
                .open();

            let mut port = match port_result {
                Ok(p) => p,
                Err(e) => {
                    println!("{}", format!("Failed to open: {}", e).red());
                    continue;
                }
            };

            // Configure port
            port.set_flow_control(serialport::FlowControl::None).ok();
            port.set_data_bits(serialport::DataBits::Eight).ok();
            port.set_parity(serialport::Parity::None).ok();
            port.set_stop_bits(serialport::StopBits::One).ok();
            port.clear(serialport::ClearBuffer::All).ok();

            // Sample data for this baud rate
            let sample_start = Instant::now();
            let mut all_bytes: Vec<u8> = Vec::new();
            let mut buffer = [0u8; 256];

            while sample_start.elapsed() < Duration::from_secs(self.args.timeout) {
                if !self.running.load(Ordering::SeqCst) {
                    break;
                }

                match port.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        all_bytes.extend_from_slice(&buffer[..n]);
                        self.stats.bytes_processed += n;
                    }
                    _ => {}
                }

                // Check if we have enough data to analyze
                if all_bytes.len() >= 50 {
                    break;
                }
            }

            if all_bytes.is_empty() {
                println!("{}", "No data".yellow());
                continue;
            }

            // Analyze the collected bytes. Keep scanning every rate and pick the
            // highest-scoring one rather than the first over the threshold: on a
            // noisy line a wrong baud can occasionally cross the threshold before
            // the true one, and the true baud is reliably the maximum.
            let score = self.calculate_readability_score(&all_bytes);
            let preview = self.get_preview(&all_bytes);

            if !self.args.quiet {
                print!("[{}] ", preview);
            }

            if score >= self.args.threshold as u32 {
                println!("{} (score: {}%)", "candidate".green().bold(), score);
            } else {
                println!("{} (score: {}%)", "low".dimmed(), score);
            }
            if score > best_score {
                best_score = score;
                best_baud = Some(baudrate);
            }
            ranked.push((baudrate, score));
        }

        self.stats.detection_time = start_time.elapsed();

        // Rank the candidates. The margin over the runner-up matters as much as
        // the winning score: a narrow margin means two rates looked alike and
        // the result should not be trusted without a second look.
        ranked.sort_by(|a, b| b.1.cmp(&a.1));
        if ranked.len() > 1 && ranked[0].1 > 0 {
            println!("\n{}", "Ranked candidates:".bold().cyan());
            for (i, (b, sc)) in ranked.iter().take(4).enumerate() {
                let line = format!("  {}. {:>7} baud  score {:>3}%", i + 1, b, sc);
                if i == 0 {
                    println!("{}", line.green().bold());
                } else {
                    println!("{}", line.dimmed());
                }
            }
        }
        let runner_up = ranked.get(1).map(|r| r.1).unwrap_or(0);
        let margin = best_score.saturating_sub(runner_up);

        match best_baud {
            Some(b) if best_score >= self.args.threshold as u32 => {
                let confidence = if margin >= 25 {
                    "high"
                } else if margin >= 10 {
                    "medium"
                } else {
                    "low"
                };
                println!(
                    "{} {} baud  (score {}%, margin {} over runner-up, confidence {})",
                    "Best match:".bold().green(),
                    b.to_string().bold(),
                    best_score,
                    margin,
                    confidence
                );
                if margin < 10 {
                    ui::warn(
                        "low confidence: the runner-up scored almost as well; re-run with a longer --timeout or verify manually",
                    );
                }
                Ok(b)
            }
            _ => Err(format!(
                "no baudrate scored at or above the --threshold of {} (best was {}%)",
                self.args.threshold, best_score
            )
            .into()),
        }
    }

    fn calculate_readability_score(&self, data: &[u8]) -> u32 {
        readability_score(data)
    }

    fn get_preview(&self, data: &[u8]) -> String {
        let preview: String = data.iter()
            .take(30)
            .map(|&b| {
                if (0x20..=0x7E).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        preview
    }

    fn save_minicom_config(&self, baudrate: u32, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let config = format!(
            "########################################################################\n\
            # Minicom configuration file - generated by baudowl\n\
            pu port             {}\n\
            pu baudrate         {}\n\
            pu bits             8\n\
            pu parity           N\n\
            pu stopbits         1\n\
            pu rtscts           No\n\
            ########################################################################",
            self.args.port, baudrate
        );

        // 1. Try the system-wide path first. `minicom <name>` reads it directly.
        let system_path = system_minicom_path(name);
        let system_err = match write_config_to(&system_path, &config) {
            Ok(()) => {
                println!(
                    "{}",
                    format!("Configuration saved to {}", system_path.display()).green()
                );
                println!("Launch it with: {}", format!("minicom {}", name).bold());
                return Ok(());
            }
            // 2. Only permission / missing-path errors warrant a fallback;
            //    anything else is a real failure we should not paper over.
            Err(e) if should_fall_back(&e) => e,
            Err(e) => {
                return Err(format!(
                    "failed to write minicom config to {}: {}",
                    system_path.display(),
                    e
                )
                .into());
            }
        };

        // 3. Fall back to the user-writable path. `minicom <name>` also reads
        //    $HOME/.minirc.<name>, so the same launch command still works.
        let home = home_dir().ok_or_else(|| {
            format!(
                "cannot write minicom config: {} not writable ({}) and $HOME is unset for a fallback",
                system_path.display(),
                system_err
            )
        })?;
        let user_path = user_minicom_path(&home, name);
        match write_config_to(&user_path, &config) {
            Ok(()) => {
                println!(
                    "{}",
                    format!(
                        "{} not writable ({}); saved to {} instead",
                        system_path.display(),
                        system_err,
                        user_path.display()
                    )
                    .yellow()
                );
                println!(
                    "Launch it with: {}   (minicom reads $HOME/.minirc.{} too)",
                    format!("minicom {}", name).bold(),
                    name
                );
                println!(
                    "{}",
                    format!(
                        "For a system-wide profile under /etc/minicom, re-run as root: sudo baudowl -n {} ...",
                        name
                    )
                    .dimmed()
                );
                Ok(())
            }
            // 4. Both locations failed: surface one clear, actionable error.
            Err(e) => Err(format!(
                "could not write minicom config to {} ({}) or {} ({})",
                system_path.display(),
                system_err,
                user_path.display(),
                e
            )
            .into()),
        }
    }

    fn launch_minicom(&self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!("{}", "Launching Minicom...".bright_blue());
        Command::new("minicom")
            .arg(name)
            .spawn()?
            .wait()?;
        Ok(())
    }

    fn print_stats(&self) {
        ui::section("=== Detection Statistics ===");
        println!("Baudrates tried: {}", self.stats.baudrates_tried);
        println!("Bytes processed: {}", self.stats.bytes_processed);
        println!("Detection time: {:.2?}", self.stats.detection_time);
        if self.stats.detection_time.as_secs() > 0 {
            let bytes_per_sec = self.stats.bytes_processed as f64 / self.stats.detection_time.as_secs_f64();
            println!("Processing speed: {:.2} bytes/sec", bytes_per_sec);
        }
    }

    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("{}", BANNER.bright_cyan());

        if self.args.baudlist {
            self.print_baudrates();
            return Ok(());
        }

        if self.args.list {
            ports::list_ports(self.args.list_all);
            return Ok(());
        }

        if self.args.list_shell_args {
            autoroot::print_presets();
            return Ok(());
        }

        // Actions that do not need baudrate auto-detection.
        if let Some(driver) = &self.args.sigrok_driver {
            match sigrok::capture_and_detect(
                driver,
                self.args.sigrok_samplerate,
                self.args.sigrok_samples,
                &self.args.sigrok_channel,
            ) {
                Ok(b) => println!("{} sigrok baud: {}", "[+]".bold().green(), b.to_string().bold()),
                Err(e) => println!("{} sigrok detect failed: {}", "[!]".red().bold(), e),
            }
            return Ok(());
        }

        let fixed_baud = self.args.baud.unwrap_or(115200);

        if let Some(profile) = &self.args.reset {
            if let Err(e) = reset::pulse_reset(&self.args.port, fixed_baud, profile) {
                ui::fail(&format!("{} {}", "Reset failed:", e));
            }
            return Ok(());
        }

        if self.args.send_break {
            if let Err(e) = reset::send_break(&self.args.port, fixed_baud, self.args.break_ms) {
                ui::fail(&format!("{} {}", "BREAK failed:", e));
            }
            return Ok(());
        }

        if self.args.detect_framing {
            framing::detect_framing(
                &self.args.port,
                fixed_baud,
                Duration::from_millis(1500),
                self.running.clone(),
            );
            return Ok(());
        }

        if self.args.mitm {
            let port_b = match &self.args.mitm_port_b {
                Some(p) => p.clone(),
                None => {
                    eprintln!("{}", "--mitm requires --mitm-port-b".red().bold());
                    return Ok(());
                }
            };
            let rules = match parse_mitm_rules(&self.args.mitm_rule) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{} {}", "Invalid --mitm-rule:".red().bold(), e);
                    return Ok(());
                }
            };
            if let Err(e) =
                mitm::mitm(&self.args.port, &port_b, fixed_baud, rules, self.running.clone())
            {
                ui::fail(&format!("{} {}", "MITM failed:", e));
            }
            return Ok(());
        }

        // Determine the baudrate: forced via --baud, otherwise auto-detect.
        // --auto forces a scan even when --baud is supplied.
        let baud = if let Some(b) = self.args.baud {
            if self.args.auto {
                println!("{}", "--auto set: scanning despite --baud".dimmed());
                match self.detect_baudrate() {
                    Ok(r) => r,
                    Err(e) => {
                        ui::fail(&format!("{} {}", "Detection failed:", e));
                        self.print_stats();
                        return Ok(());
                    }
                }
            } else {
                println!(
                    "{} {}",
                    "Using forced baudrate:".bright_green(),
                    b.to_string().bold()
                );
                b
            }
        } else {
            match self.detect_baudrate() {
                Ok(r) => {
                    println!(
                        "\n{} {} {}",
                        "🦉 HOOT!".bold().yellow(),
                        "Detected baudrate:".bright_green(),
                        r.to_string().bold()
                    );
                    r
                }
                Err(e) => {
                    ui::fail(&format!("{} {}", "Detection failed:", e));
                    self.print_stats();
                    return Ok(());
                }
            }
        };

        // U-Boot memory write (patch primitive).
        if let Some(addr) = &self.args.write_mem {
            let res = (|| -> Result<(), Box<dyn std::error::Error>> {
                let a = parse_num(addr)?;
                let v = parse_num(&self.args.write_value)?;
                if v > 0xff {
                    return Err("write value must be a byte (0-255)".into());
                }
                let c = parse_num(&self.args.write_count)?;
                uboot::write_flow(
                    &self.args.port,
                    baud,
                    a,
                    v as u8,
                    c,
                    &autoroot::parse_interrupt_key(&self.args.interrupt_key)?,
                    Duration::from_secs(self.args.break_timeout),
                    self.running.clone(),
                )
            })();
            if let Err(e) = res {
                ui::fail(&format!("{} {}", "Memory write failed:", e));
            }
            return Ok(());
        }

        // Firmware dump (flash or RAM) over U-Boot.
        if self.args.dump_flash || self.args.dump_mem.is_some() {
            let res = (|| -> Result<(), Box<dyn std::error::Error>> {
                let (source, offset) = if let Some(addr) = &self.args.dump_mem {
                    (uboot::FlashSource::Ram, parse_num(addr)?)
                } else {
                    let src = uboot::FlashSource::parse(&self.args.dump_source).ok_or_else(|| {
                        format!("bad --dump-source '{}' (sf|nand|mmc)", self.args.dump_source)
                    })?;
                    (src, parse_num(&self.args.dump_offset)?)
                };
                let opts = uboot::DumpOpts {
                    source,
                    ram_addr: parse_num(&self.args.dump_ram_addr)?,
                    offset,
                    length: parse_num(&self.args.dump_length)?,
                    chunk: parse_num(&self.args.dump_chunk)?,
                    out_path: self.args.dump_out.clone(),
                    interrupt_key: autoroot::parse_interrupt_key(&self.args.interrupt_key)?,
                    break_timeout: Duration::from_secs(self.args.break_timeout),
                    prompt: None,
                };
                uboot::dump(&self.args.port, baud, &opts, self.running.clone())
            })();
            if let Err(e) = res {
                ui::fail(&format!("{} {}", "Dump failed:", e));
            }
            return Ok(());
        }

        if let Some(remote) = &self.args.shell_dump {
            if let Err(e) = uboot::shell_dump(
                &self.args.port,
                baud,
                remote,
                &self.args.dump_out,
                self.running.clone(),
            ) {
                ui::fail(&format!("{} {}", "Shell dump failed:", e));
            }
            return Ok(());
        }

        if self.args.detect_protocol {
            let data = sample_bytes(&self.args.port, baud, Duration::from_secs(2), self.running.clone());
            match framing::detect_protocol(&data) {
                Some(p) => println!("{} protocol: {}", "[+]".bold().green(), p.bold()),
                None => println!("{} no known binary protocol in {} bytes", "[-]".yellow(), data.len()),
            }
            return Ok(());
        }

        if let Some(path) = &self.args.script {
            let res = (|| -> Result<(), Box<dyn std::error::Error>> {
                let text = std::fs::read_to_string(path)?;
                let steps = script::parse_script(&text)?;
                script::run_script(&self.args.port, baud, &steps, self.running.clone())
            })();
            if let Err(e) = res {
                ui::fail(&format!("{} {}", "Script failed:", e));
            }
            return Ok(());
        }

        if self.args.cred_brute {
            match recon::cred_brute(
                &self.args.port,
                baud,
                &recon::default_creds(),
                self.running.clone(),
            ) {
                Ok(Some((u, p))) => {
                    println!("{} valid login {}:{}", "[+]".bold().green(), u, p)
                }
                Ok(None) => {}
                Err(e) => println!("\n{} {}", "Credential test failed:".red().bold(), e),
            }
            return Ok(());
        }

        if self.args.harvest {
            if let Err(e) = recon::harvest(
                &self.args.port,
                baud,
                Some(&self.args.dump_out),
                self.running.clone(),
            ) {
                ui::fail(&format!("{} {}", "Harvest failed:", e));
            }
            return Ok(());
        }

        if let Some(pattern) = &self.args.glitch_on {
            let opts = glitch::GlitchOpts {
                pattern: pattern.clone(),
                line: glitch::TriggerLine::parse(&self.args.glitch_line),
                pulse_us: self.args.glitch_pulse_us,
                command: self.args.glitch_cmd.clone(),
                timeout: Duration::from_secs(self.args.glitch_timeout),
            };
            if let Err(e) =
                glitch::watch_and_trigger(&self.args.port, baud, &opts, self.running.clone())
            {
                ui::fail(&format!("{} {}", "Glitch watch failed:", e));
            }
            return Ok(());
        }

        // Passive capture (read-only) and replay.
        if self.args.sniff {
            let opts = sniff::SniffOpts {
                out: self.args.sniff_out.clone(),
                max_bytes: self.args.sniff_max,
                decode: self.args.sniff_decode,
                idle_gap_us: self.args.sniff_idle_us,
                reset: self.args.sniff_reset.clone(),
            };
            if let Err(e) = sniff::sniff(&self.args.port, baud, &opts, self.running.clone()) {
                ui::fail(&format!("{} {}", "Sniff failed:", e));
            }
            return Ok(());
        }

        if let Some(file) = &self.args.replay {
            if let Err(e) = sniff::replay(
                &self.args.port,
                baud,
                file,
                self.args.replay_chunk,
                self.args.replay_delay_ms,
                self.running.clone(),
            ) {
                ui::fail(&format!("{} {}", "Replay failed:", e));
            }
            return Ok(());
        }

        // Timing side-channel attack (recover a secret by response timing).
        if self.args.timing_attack {
            let opts = timing::TimingOpts {
                charset: self.args.timing_charset.bytes().collect(),
                max_len: self.args.timing_maxlen,
                samples: self.args.timing_samples,
                marker: self.args.timing_marker.clone(),
                prefix: self.args.timing_prefix.clone(),
                z: self.args.timing_z,
                settle: Duration::from_millis(self.args.timing_settle_ms),
            };
            if let Err(e) = timing::timing_attack(&self.args.port, baud, &opts, self.running.clone())
            {
                ui::fail(&format!("{} {}", "Timing attack failed:", e));
            }
            return Ok(());
        }

        if self.args.leakage_test {
            if let Err(e) = timing::leakage_test(
                &self.args.port,
                baud,
                &self.args.timing_class_a,
                &self.args.timing_class_b,
                self.args.timing_samples,
                &self.args.timing_marker,
                self.running.clone(),
            ) {
                ui::fail(&format!("{} {}", "Leakage test failed:", e));
            }
            return Ok(());
        }

        // Serial fuzzer with crash oracle, auto-reset, and minimization.
        if self.args.fuzz {
            let seed_input = self
                .args
                .fuzz_seed_input
                .clone()
                .unwrap_or_default()
                .into_bytes();
            let crash_sigs = if self.args.fuzz_crash_sig.is_empty() {
                fuzz::default_crash_signatures()
            } else {
                let mut s = fuzz::default_crash_signatures();
                s.extend(self.args.fuzz_crash_sig.iter().cloned());
                s
            };
            let proto = self.args.fuzz_protocol.to_ascii_lowercase();
            if !matches!(proto.as_str(), "raw" | "modbus" | "nmea") {
                eprintln!(
                    "{} invalid --fuzz-protocol '{}' (raw|modbus|nmea)",
                    "Error:".red().bold(),
                    self.args.fuzz_protocol
                );
                return Ok(());
            }
            let reset_mode = self.args.fuzz_reset.to_ascii_lowercase();
            if !matches!(reset_mode.as_str(), "dtr" | "rts" | "cmd" | "none") {
                eprintln!(
                    "{} invalid --fuzz-reset '{}' (dtr|rts|cmd|none)",
                    "Error:".red().bold(),
                    self.args.fuzz_reset
                );
                return Ok(());
            }
            let opts = fuzz::FuzzOpts {
                seed_input,
                max_len: self.args.fuzz_maxlen,
                iterations: self.args.fuzz_iterations,
                response_timeout: Duration::from_millis(self.args.fuzz_timeout_ms),
                crash_sigs,
                reset: fuzz::ResetMode::parse(&self.args.fuzz_reset),
                reset_cmd: self.args.fuzz_reset_cmd.clone(),
                seed: self.args.fuzz_seed,
                newline: !self.args.fuzz_no_newline,
                proto: fuzz::Proto::parse(&self.args.fuzz_protocol),
            };
            if let Err(e) = fuzz::run_fuzz(&self.args.port, baud, &opts, self.running.clone()) {
                ui::fail(&format!("{} {}", "Fuzz failed:", e));
            }
            return Ok(());
        }

        // Autoroot path: break into U-Boot and enable a shell.
        if self.args.autoroot {
            let interrupt_key = match autoroot::parse_interrupt_key(&self.args.interrupt_key) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("{} {}", "Invalid --interrupt-key:".red().bold(), e);
                    return Ok(());
                }
            };
            let opts = autoroot::AutoRootOpts {
                shell_arg: autoroot::resolve_shell_arg(&self.args.shell_arg),
                interrupt_key,
                break_timeout: Duration::from_secs(self.args.break_timeout),
                single: self.args.single,
                boot_cmd: self.args.boot_cmd.clone(),
                persist: self.args.persist,
                dry_run: self.args.dry_run,
                extra_prompts: Vec::new(),
            };
            if let Err(e) = autoroot::run(&self.args.port, baud, &opts, self.running.clone()) {
                ui::fail(&format!("{} {}", "Autoroot failed:", e));
            }
            return Ok(());
        }

        // Default path: save and launch a minicom profile if a name was given.
        if let Some(name) = &self.args.name.clone() {
            self.save_minicom_config(baud, name)?;
            self.launch_minicom(name)?;
        }

        // Stay connected instead of exiting the moment the rate is known.
        if self.args.monitor || self.args.interactive {
            let mode = if self.args.interactive {
                "interactive (type to send, Ctrl-C exits)"
            } else {
                "read-only (Ctrl-C exits)"
            };
            ui::step("*", &format!("Connected at {} baud, {}", baud, mode));
            println!();
            match session::Session::open(&self.args.port, baud, self.running.clone()) {
                Ok(mut s) => {
                    let r = if self.args.interactive {
                        s.interactive()
                    } else {
                        s.monitor(self.args.monitor_raw)
                    };
                    if let Err(e) = r {
                        ui::fail(&format!("session ended: {}", e));
                    }
                }
                Err(e) => ui::fail(&format!("could not open {}: {}", self.args.port, e)),
            }
            return Ok(());
        }

        self.print_stats();
        if !self.args.quiet {
            ui::step(
                "*",
                "Use --monitor to stay connected, or --interactive to send commands",
            );
        }
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.no_color || ui::no_color_env() {
        ui::set_color(false);
    }
    let mut hound = match BaudOwl::new(args) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            std::process::exit(1);
        }
    };
    hound.run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_path_is_under_etc_minicom() {
        assert_eq!(
            system_minicom_path("rk3399"),
            PathBuf::from("/etc/minicom/minirc.rk3399")
        );
    }

    #[test]
    fn user_path_joins_home_with_dot_minirc() {
        assert_eq!(
            user_minicom_path(Path::new("/home/tester"), "rk3399"),
            PathBuf::from("/home/tester/.minirc.rk3399")
        );
    }

    #[test]
    fn fallback_only_on_permission_or_not_found() {
        assert!(should_fall_back(&io::Error::from(io::ErrorKind::PermissionDenied)));
        assert!(should_fall_back(&io::Error::from(io::ErrorKind::NotFound)));
        assert!(!should_fall_back(&io::Error::from(io::ErrorKind::AlreadyExists)));
        assert!(!should_fall_back(&io::Error::from(io::ErrorKind::Other)));
    }


    // Ground truth for the scorer: bytes a real UART receiver produces when it
    // samples a 115200-baud U-Boot banner at the wrong rate. Generated with a
    // bit-level 8N1 simulator (start-bit hunt, 1.5-bit first sample, resync on
    // the stop bit), not hand-written noise.
    const TRUE_115200: &[u8] = b"\x55\x2d\x42\x6f\x6f\x74\x20\x32\x30\x31\x38\x2e\x30\x33\x20\x28\x4a\x61\x6e\x20\x30\x31\x20\x32\x30\x32\x30\x20\x2d\x20\x30\x30\x3a\x30\x30\x3a\x30\x30\x29\x20\x62\x6f\x61\x72\x64\x2d\x78\x79\x7a\x0d\x0a\x44\x52\x41\x4d\x3a\x20\x20\x35\x31\x32\x20\x4d\x69\x42\x0d\x0a\x4e\x41\x4e\x44\x3a\x20\x20\x32\x35\x36\x20\x4d\x69\x42\x0d\x0a\x49\x6e\x3a\x20\x20\x20\x20\x73\x65\x72\x69\x61\x6c\x0d\x0a\x4f\x75\x74\x3a\x20\x20\x20\x73\x65\x72\x69\x61\x6c\x0d\x0a\x45\x72\x72\x3a\x20\x20\x20\x73\x65\x72\x69\x61\x6c\x0d\x0a";
    const WRONG_38400: &[u8] = b"\x7a\xbb\xb0\x70\x30\x21\xb3\xf0\xb0\x38\xf0\xf0\x30\x70\x32\xb1\x6b\x22\x33\xb8\x30\x23\x29\xeb\xf0\x38\x73\x21\x33\x30\xfa\x33\x61\xfa\x30\xfa\x33\x21\xf2\x30\xfa\x33\x61\xfa\x30\x3a\x68\xb3\x70\x73\x32\x3a\x7a\x32\x7a\x7a\x32\x30\xa1\x31\x29\x7a\xf2\xb0\xf1\x70\x3a\x30\xf0\x30\xb0\xb1\xb1\x71\xf3\xba\x33\xe9\xea\xb0\x30\x73\x61\x2a\x31\xf8\x28\x6a\xfb\x30\x30\x32\x6b\xbb\x31\x30\x32\x6b\xf2\x31\x30\x32\x6b\xbb\x31\xb8\x33\x21\x32\x33\xbb\x78\xb0\x33\xba\x73\xfb\xf0\x68\x39\xa1\x61\x3b\xb0\xb9\x30\x73\xb0";
    const WRONG_57600: &[u8] = b"\x3f\xbc\xed\x48\x5a\x2a\x5a\x08\x9c\x0d\x5a\x48\x4a\x0a\x09\x4a\x4a\x4a\x4a\x08\xbc\xcc\x3d\xde\x3e\xa8\x9e\x4d\x08\x5b\x0a\x9d\x3c\xa8\xac\x4d\x08\x7a\x0b\x9d\x3c\x98\x4d\x08\x08\xbe\x9e\xac\x09\xfd\x4f\x08\xd8\xcd\x9c\x3d\xb8\xce\x0a\x08\xbe\x9e\xac\x09\xbd\x4f\x08\xb8\x8f\x3a\x88\xec\x98\xdd\x98\xdd\xe8\x0d\xee\xcd\x98\xef\x8d\xbd\x4f\x08\x0a\x09\x6b\x38\xf8\x89\xbd\x0f\x4a\x4a\x49\x0a\x88\xac\x48\x0a\x4a\x4a\x38\x48\x4a\x4a\x4a\x1a\x88\x9d\xae\xc9\xce\x09\xcd\xbc\x0a\x78\x4a\xb8\x8c\x09\x9d\xad\x0a\x48";
    const WRONG_230400: &[u8] = b"\x66\x66\x9e\x18\x80\xe6\x9e\xfe\x9e\x60\x06\x18\x78\x00\x98\xe0\x18\x18\x86\x00\x98\x78\x00\x18\x86\x98\x98\x06\x86\x9e\x00\x18\x98\xe0\x18\x18\x78\x00\x18\x78\x00\x18\x98\x9e\x18\x18\x18\x18\x7e\x00\x18\x18\x7e\x00\x18\x98\x98\x18\x18\xe0\xe6\x9e\x06\x86\xf8\x06\x78\xe6\x86\x80\x66\x86\xfe\x66\x80\x98\x80\x60\x86\x98\x66\x66\x98\x98\x18\x18\x98\xe6\x98\xe0\x18\x78\x00\x98\x1e\x66\x9e\x18\x66\x80\x98\x80\xf8\x98\x06\x86\x98\x60\x86\x7e\x00\x18\x18\x78\x66\x18\x1e\x00\x98\x1e\x66\x9e\x18\x66\x80\x98\x80\x86";
    const WRONG_9600: &[u8] = b"\x14\x48\x18\xd5\x09\x61\x94\xc8\x1c\xd6\x7c\x10\x8c\x10\x31\xbb\x18\x49\x14\xee\x86\x04\xd5\xc4\xfb\x94\x39\xce\x4c\x21\xc4\x1c\x85\xad\xd5\x09\x61\x94\xc8\x1c\xd6\x7c\x10\x8c\x10\x31";

    #[test]
    fn scorer_separates_true_baud_from_wrong_baud() {
        let t = readability_score(TRUE_115200);
        let wrong = [
            readability_score(WRONG_38400),
            readability_score(WRONG_57600),
            readability_score(WRONG_230400),
            readability_score(WRONG_9600),
        ];
        let worst = *wrong.iter().max().unwrap();
        // The true rate must clear the default --threshold of 60 with room to
        // spare, and beat every wrong rate by a wide margin. Measured at the
        // time of writing: true 90, worst wrong 53.
        assert!(t >= 85, "true baud scored {}, expected >= 85", t);
        assert!(worst <= 60, "worst wrong baud scored {}, expected <= 60", worst);
        assert!(
            t - worst >= 25,
            "separation {} too small (true {}, worst wrong {})",
            t - worst,
            t,
            worst
        );
    }

    #[test]
    fn scorer_rejects_pathological_input() {
        assert_eq!(readability_score(b""), 0);
        // all high-bit, all null, all 0xff must all score near zero
        assert!(readability_score(&[0x80u8; 64]) < 20);
        assert!(readability_score(&[0x00u8; 64]) < 20);
        assert!(readability_score(&[0xffu8; 64]) < 20);
        // clean ASCII prose scores high
        assert!(readability_score(b"root@target:/# cat /proc/version\r\nLinux 4.9\r\n") > 80);
    }

    #[test]
    fn hex_parsing_survives_multibyte() {
        // Regression: `&clean[i..i + 2]` panicked on multibyte input because the
        // str slice landed mid-codepoint. Must error, never panic.
        for s in ["€€", "\u{1F4A9}\u{1F4A9}", "de€d", "a2b:€€:4142", "é9"] {
            let _ = parse_hex_bytes(s);
            let _ = parse_mitm_rules(&[s.to_string()]);
        }
        assert!(parse_hex_bytes("€€").is_err());
        assert_eq!(parse_hex_bytes("de ad").unwrap(), vec![0xde, 0xad]);
    }

    /// Self-fuzz: throw pseudorandom and adversarial bytes at every text parser
    /// in the crate. None of them may panic. This guards the whole
    /// "slice user input by byte index" bug class, not just the known cases.
    #[test]
    fn parsers_never_panic_on_hostile_input() {
        let mut prng = crate::fuzz::Prng::new(0xBAD5EED);
        // A corpus of bytes that historically break naive parsers.
        let seeds: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"\xff\xfe\xfd".to_vec(),
            "€".as_bytes().to_vec(),
            "\u{1F4A9}".as_bytes().to_vec(),
            b"$GP*\xe2\x82\xac".to_vec(),
            b"\x00\x24\x2a\xf0\x9f\x92\xa9".to_vec(),
            b"0: \xff\xff  junk".to_vec(),
            b"\\x".to_vec(),
            b"sendraw \xc3".to_vec(),
        ];

        let mut cases = seeds;
        for _ in 0..600 {
            let len = prng.below(48);
            cases.push((0..len).map(|_| prng.byte()).collect());
        }

        for raw in &cases {
            let text = String::from_utf8_lossy(raw);

            // byte-oriented parsers
            let _ = crate::framing::detect_protocol(raw);
            let _ = crate::framing::printable_score(raw);
            let _ = crate::framing::modbus_crc16(raw);
            let _ = crate::framing::nmea_checksum(raw);
            let events: Vec<(u64, u8)> =
                raw.iter().enumerate().map(|(i, &b)| (i as u64 * 7, b)).collect();
            let _ = crate::sniff::split_frames(&events, 100);
            let _ = crate::sigrok::baud_from_samples(raw, 1_000_000);
            let _ = crate::fuzz::looks_like_crash(&text, &crate::fuzz::default_crash_signatures());

            // text-oriented parsers (the byte-index slicing bug class)
            let _ = crate::uboot::parse_md_b(&text);
            let _ = crate::uboot::decode_base64(&text);
            let _ = crate::recon::extract_secrets(&text);
            let _ = crate::autoroot::parse_interrupt_key(&text);
            let _ = crate::autoroot::resolve_shell_arg(&text);
            let _ = crate::autoroot::build_shell_bootargs(&text, "init=/bin/sh", true);
            let _ = crate::script::parse_script(&text);
            let _ = parse_hex_bytes(&text);
            let _ = parse_num(&text);
            let _ = parse_mitm_rules(&[text.to_string()]);
        }
    }
}
