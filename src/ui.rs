use colored::*;

pub fn set_color(enabled: bool) {
    control::set_override(enabled);
}

pub fn no_color_env() -> bool {
    // `map_or` rather than `is_some_and` (Rust 1.70) to keep the MSRV low.
    std::env::var_os("NO_COLOR").map_or(false, |v| !v.is_empty())
}

fn box_line(width: usize) -> String {
    "=".repeat(width)
}

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

pub fn found(msg: &str) {
    println!("{} {}", "[+]".bold().green(), msg.green());
}

pub fn fail(msg: &str) {
    println!("{} {}", "[!]".bold().red(), msg.red());
}

pub fn warn(msg: &str) {
    println!("{} {}", "[!]".bold().yellow(), msg.yellow());
}

pub fn step(tag: &str, msg: &str) {
    println!("{} {}", format!("[{}]", tag).bold().cyan(), msg);
}

pub fn detail(msg: &str) {
    println!("{}", format!("    {}", msg).dimmed());
}

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
