//! Semantic terminal output. Colour carries meaning, so an operator can tell
//! at a glance what happened without reading the text:
//!
//!   win     bright green, boxed   the objective was achieved (root shell,
//!                                 credentials, firmware, a crash)
//!   found   green                 a positive intermediate result
//!   fail    red                   the operation failed
//!   danger  bright red, boxed     destructive or persistent change
//!   warn    yellow                proceed with caution
//!   step    cyan                  phase progress
//!   detail  dimmed                low-signal noise (rejected guesses, etc.)
//!
//! Colour is disabled automatically when stdout is not a terminal, when NO_COLOR
//! is set, or with --no-color, so redirected output stays clean text.

use colored::*;

/// Force colour on or off. Called once at startup from the CLI.
pub fn set_color(enabled: bool) {
    control::set_override(enabled);
}

/// Honour the NO_COLOR convention (https://no-color.org).
pub fn no_color_env() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

fn box_line(width: usize) -> String {
    "=".repeat(width)
}

/// The headline result. Boxed and bright green so it stands out in a long
/// scrollback: this is what the operator was trying to achieve.
pub fn win(title: &str, detail: &str) {
    let body = if detail.is_empty() {
        title.to_string()
    } else {
        format!("{}  {}", title, detail)
    };
    let width = body.chars().count().max(title.chars().count()) + 4;
    println!();
    println!("{}", box_line(width).bright_green().bold());
    println!("{}", format!("  {}  ", body).bright_green().bold());
    println!("{}", box_line(width).bright_green().bold());
}

/// A destructive or persistent change is about to happen / just happened.
pub fn danger(title: &str, detail: &str) {
    let body = if detail.is_empty() {
        title.to_string()
    } else {
        format!("{}  {}", title, detail)
    };
    let width = body.chars().count() + 4;
    println!();
    println!("{}", box_line(width).bright_red().bold());
    println!("{}", format!("  {}  ", body).bright_red().bold());
    println!("{}", box_line(width).bright_red().bold());
}

/// A positive intermediate result.
pub fn found(msg: &str) {
    println!("{} {}", "[+]".bold().green(), msg.green());
}

/// The operation failed.
pub fn fail(msg: &str) {
    println!("{} {}", "[!]".bold().red(), msg.red());
}

/// Something worth noticing but not fatal.
pub fn warn(msg: &str) {
    println!("{} {}", "[!]".bold().yellow(), msg.yellow());
}

/// Phase progress. `tag` is a short marker such as "A" or "*".
pub fn step(tag: &str, msg: &str) {
    println!("{} {}", format!("[{}]", tag).bold().cyan(), msg);
}

/// Low-signal detail: rejected guesses, per-iteration chatter.
pub fn detail(msg: &str) {
    println!("{}", format!("    {}", msg).dimmed());
}

/// Section heading for a mode (dump, fuzz, sniff...).
pub fn section(title: &str) {
    println!("\n{}", title.bold().magenta());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_do_not_panic_with_any_input() {
        // Output helpers must tolerate empty, huge, and multibyte input: they
        // compute a box width from the text, and a char/byte mix-up here would
        // be the same class of bug as the parser panics fixed in 1.6.1.
        set_color(false);
        for s in ["", "ok", "€€€", "\u{1F4A9} root", &"x".repeat(500)] {
            win(s, s);
            danger(s, s);
            found(s);
            fail(s);
            warn(s);
            step(s, s);
            detail(s);
            section(s);
        }
    }

    #[test]
    fn box_width_counts_chars_not_bytes() {
        // "€" is 3 bytes but 1 column; using len() would over-pad the box.
        assert_eq!(box_line("€€".chars().count() + 4).len(), 6);
    }
}
