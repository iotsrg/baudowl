use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use colored::*;
use serialport::{DataBits, Parity, StopBits};

pub fn modbus_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

pub fn nmea_checksum(body: &[u8]) -> u8 {
    body.iter().fold(0u8, |a, &b| a ^ b)
}

pub fn modbus_frame(addr: u8, func: u8, data: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(4 + data.len());
    f.push(addr);
    f.push(func);
    f.extend_from_slice(data);
    let crc = modbus_crc16(&f);
    f.extend_from_slice(&crc.to_le_bytes());
    f
}

pub fn nmea_sentence(body: &str) -> String {
    format!("${}*{:02X}\r\n", body, nmea_checksum(body.as_bytes()))
}

fn looks_like_modbus(data: &[u8]) -> bool {
    let max = data.len().min(256);
    for end in 4..=max {
        let crc = modbus_crc16(&data[..end - 2]);
        let got = u16::from_le_bytes([data[end - 2], data[end - 1]]);
        if crc == got {
            return true;
        }
    }
    false
}

fn looks_like_nmea(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    for line in text.split(['\r', '\n']) {
        let dollar = match line.find('$') {
            Some(i) => i,
            None => continue,
        };
        let star = match line[dollar..].find('*') {
            Some(i) => dollar + i,
            None => continue,
        };
        if star + 3 > line.len() {
            continue;
        }
        let body = &line.as_bytes()[dollar + 1..star];
        // Slice the two checksum digits as bytes, not as a str: `line` is a lossy
        // decode of raw serial data, so a multibyte char after '*' would make a
        // str slice land mid-codepoint and panic. Bounds are already guaranteed
        // by the `star + 3 > line.len()` check above; non-ASCII digits simply
        // fail to parse and are skipped.
        let given = &line.as_bytes()[star + 1..star + 3];
        if let Some(want) = std::str::from_utf8(given)
            .ok()
            .and_then(|g| u8::from_str_radix(g, 16).ok())
        {
            if nmea_checksum(body) == want && !body.is_empty() {
                return true;
            }
        }
    }
    false
}

fn looks_like_mavlink(data: &[u8]) -> bool {
    let n = data.len();
    for i in 0..n {
        match data[i] {
            0xFE if i + 8 <= n => {
                let len = data[i + 1] as usize;
                if i + 8 + len <= n {
                    return true;
                }
            }
            0xFD if i + 12 <= n => {
                let len = data[i + 1] as usize;
                if i + 12 + len <= n {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

pub fn detect_protocol(data: &[u8]) -> Option<&'static str> {
    if data.len() < 4 {
        return None;
    }
    if looks_like_nmea(data) {
        return Some("NMEA 0183 (GPS/GNSS)");
    }
    if looks_like_modbus(data) {
        return Some("Modbus RTU");
    }
    if looks_like_mavlink(data) {
        return Some("MAVLink (framing only, CRC not checked)");
    }
    None
}

#[derive(Clone, Copy)]
pub struct Framing {
    pub label: &'static str,
    pub data_bits: DataBits,
    pub parity: Parity,
    pub stop_bits: StopBits,
}

pub fn framing_combos() -> Vec<Framing> {
    use DataBits::{Eight, Seven};
    use Parity::{Even, Odd};
    use StopBits::{One, Two};
    vec![
        Framing { label: "8N1", data_bits: Eight, parity: Parity::None, stop_bits: One },
        Framing { label: "7E1", data_bits: Seven, parity: Even, stop_bits: One },
        Framing { label: "7O1", data_bits: Seven, parity: Odd, stop_bits: One },
        Framing { label: "8E1", data_bits: Eight, parity: Even, stop_bits: One },
        Framing { label: "8O1", data_bits: Eight, parity: Odd, stop_bits: One },
        Framing { label: "8N2", data_bits: Eight, parity: Parity::None, stop_bits: Two },
        Framing { label: "7N1", data_bits: Seven, parity: Parity::None, stop_bits: One },
    ]
}

pub fn printable_score(data: &[u8]) -> u32 {
    if data.is_empty() {
        return 0;
    }
    let printable = data
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b) || matches!(b, b'\n' | b'\r' | b'\t'))
        .count();
    (printable * 100 / data.len()) as u32
}

pub fn detect_framing(
    port: &str,
    baud: u32,
    per_combo: Duration,
    running: Arc<AtomicBool>,
) -> Option<&'static str> {
    println!("\n{}", "=== FRAMING AUTODETECT ===".bold().magenta());
    println!("{} {} @ {} baud", "Target:".cyan(), port, baud);
    let mut best: Option<(u32, &'static str)> = None;
    for f in framing_combos() {
        if !running.load(Ordering::SeqCst) {
            break;
        }
        let open = serialport::new(port, baud)
            .data_bits(f.data_bits)
            .parity(f.parity)
            .stop_bits(f.stop_bits)
            .timeout(Duration::from_millis(100))
            .open();
        let mut p = match open {
            Ok(p) => p,
            Err(e) => {
                println!("  {:<4} {}", f.label, format!("open failed: {}", e).red());
                continue;
            }
        };
        p.clear(serialport::ClearBuffer::All).ok();
        let mut buf = [0u8; 512];
        let mut data = Vec::new();
        let deadline = Instant::now() + per_combo;
        while Instant::now() < deadline && data.len() < 256 {
            if let Ok(n) = p.read(&mut buf) {
                data.extend_from_slice(&buf[..n]);
            }
        }
        let score = printable_score(&data);
        println!("  {:<4} score {:>3}%  ({} bytes)", f.label.bold(), score, data.len());
        if !data.is_empty() && best.map(|(s, _)| score > s).unwrap_or(true) {
            best = Some((score, f.label));
        }
    }
    match best {
        Some((s, label)) if s > 0 => {
            println!("{} best framing: {} ({}%)", "[+]".bold().green(), label.bold(), s);
            Some(label)
        }
        _ => {
            println!("{}", "no readable framing found (line may be silent or binary)".yellow());
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modbus_crc_known_vector() {
        // Canonical CRC-16/MODBUS check value over ASCII "123456789".
        assert_eq!(modbus_crc16(b"123456789"), 0x4B37);
        // Round-trip: append the computed CRC and confirm detection.
        let frame = [0x01u8, 0x04, 0x02, 0xFF, 0xFF];
        let crc = modbus_crc16(&frame);
        let mut full = frame.to_vec();
        full.extend_from_slice(&crc.to_le_bytes());
        assert!(looks_like_modbus(&full));
    }

    #[test]
    fn nmea_checksum_and_detect() {
        // GPGGA sample, checksum 0x47 over the body
        let body = b"GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,";
        let cs = nmea_checksum(body);
        let line = format!("${}*{:02X}\r\n", String::from_utf8_lossy(body), cs);
        assert!(looks_like_nmea(line.as_bytes()));
        assert_eq!(detect_protocol(line.as_bytes()), Some("NMEA 0183 (GPS/GNSS)"));
    }

    #[test]
    fn nmea_bad_checksum_rejected() {
        let line = b"$GPGGA,123519,4807.038,N*00\r\n";
        assert!(!looks_like_nmea(line));
    }

    #[test]
    fn mavlink_structural() {
        // v1: FE len ... ; len=2 payload, total 8+2
        let frame = [0xFEu8, 0x02, 0x00, 0x01, 0x01, 0x00, 0xAA, 0xBB, 0x12, 0x34];
        assert!(looks_like_mavlink(&frame));
    }

    #[test]
    fn printable_score_text_vs_noise() {
        assert!(printable_score(b"hello world\n") > 90);
        assert!(printable_score(&[0x00, 0xff, 0x80, 0x01, 0xfe]) < 30);
    }

    #[test]
    fn builds_valid_frames() {
        let f = modbus_frame(0x01, 0x03, &[0x00, 0x00, 0x00, 0x0a]);
        assert!(looks_like_modbus(&f));
        let s = nmea_sentence("GPGGA,123519,4807.038,N");
        assert!(looks_like_nmea(s.as_bytes()));
        assert_eq!(detect_protocol(s.as_bytes()), Some("NMEA 0183 (GPS/GNSS)"));
    }

    #[test]
    fn nmea_decode_survives_binary_garbage() {
        // Regression: `&line[star+1..star+3]` panicked when a multibyte char (or
        // a lossy-decoded U+FFFD from an invalid byte) followed '*', because the
        // slice landed mid-codepoint. These must return without panicking.
        for junk in [
            &b"$*\xff"[..],                 // '*' then one invalid byte -> U+FFFD
            &b"$GP*\xe2\x82\xac"[..],       // '*' then a 3-byte '€'
            &b"$\xff\xff*\x80\x80"[..],     // continuation bytes around the frame
            &b"\x00\x24\x2a\xf0\x9f\x92\xa9"[..], // '$' '*' then a 4-byte emoji
        ] {
            let _ = looks_like_nmea(junk);
            let _ = detect_protocol(junk);
        }
        // A real sentence must still decode after the fix.
        let s = nmea_sentence("GPRMC,081836,A,3751.65,S");
        assert!(looks_like_nmea(s.as_bytes()));
    }
}
