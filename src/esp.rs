use std::error::Error;
use std::io::{self};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

use colored::*;

use crate::ui;
use crate::xfer::{ByteChannel, SerialChannel};

const SLIP_END: u8 = 0xc0;
const SLIP_ESC: u8 = 0xdb;
const SLIP_ESC_END: u8 = 0xdc;
const SLIP_ESC_ESC: u8 = 0xdd;

const DIR_REQ: u8 = 0x00;
const DIR_RESP: u8 = 0x01;
const CMD_SYNC: u8 = 0x08;
const CMD_READ_REG: u8 = 0x0a;

fn other<E: Into<Box<dyn std::error::Error + Send + Sync>>>(msg: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}

pub fn slip_encode(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 2);
    out.push(SLIP_END);
    for &b in payload {
        match b {
            SLIP_END => out.extend_from_slice(&[SLIP_ESC, SLIP_ESC_END]),
            SLIP_ESC => out.extend_from_slice(&[SLIP_ESC, SLIP_ESC_ESC]),
            _ => out.push(b),
        }
    }
    out.push(SLIP_END);
    out
}

pub fn read_frame(ch: &mut dyn ByteChannel, overall: Duration) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + overall;
    // Skip to the first frame delimiter.
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "no SLIP frame start"));
        }
        match ch.read_byte(Duration::from_millis(200))? {
            Some(SLIP_END) => break,
            _ => continue,
        }
    }
    let mut payload = Vec::new();
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "unterminated SLIP frame"));
        }
        match ch.read_byte(Duration::from_millis(200))? {
            Some(SLIP_END) => {
                if payload.is_empty() {
                    continue; // back-to-back delimiters; keep reading
                }
                return Ok(payload);
            }
            Some(SLIP_ESC) => match ch.read_byte(Duration::from_millis(200))? {
                Some(SLIP_ESC_END) => payload.push(SLIP_END),
                Some(SLIP_ESC_ESC) => payload.push(SLIP_ESC),
                Some(b) => payload.push(b), // tolerate a stray ESC
                None => {}
            },
            Some(b) => payload.push(b),
            None => {}
        }
    }
}

fn build_request(cmd: u8, data: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + data.len());
    p.push(DIR_REQ);
    p.push(cmd);
    p.extend_from_slice(&(data.len() as u16).to_le_bytes());
    p.extend_from_slice(&0u32.to_le_bytes()); // checksum
    p.extend_from_slice(data);
    p
}

fn parse_response(cmd: u8, payload: &[u8]) -> io::Result<(u32, Vec<u8>)> {
    if payload.len() < 8 {
        return Err(other("short ESP response"));
    }
    if payload[0] != DIR_RESP {
        return Err(other("not a response packet"));
    }
    if payload[1] != cmd {
        return Err(other(format!(
            "response for command {:#x}, expected {:#x}",
            payload[1], cmd
        )));
    }
    let size = u16::from_le_bytes([payload[2], payload[3]]) as usize;
    let value = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let data_end = (8 + size).min(payload.len());
    let data = payload[8..data_end].to_vec();
    if data.len() >= 2 && data[data.len() - 2] != 0 {
        return Err(other(format!(
            "ESP command {:#x} failed, status code {:#x}",
            cmd,
            data[data.len() - 1]
        )));
    }
    Ok((value, data))
}

fn command(
    ch: &mut dyn ByteChannel,
    cmd: u8,
    data: &[u8],
    timeout: Duration,
) -> io::Result<(u32, Vec<u8>)> {
    ch.write_all(&slip_encode(&build_request(cmd, data)))?;
    ch.flush()?;
    // The ROM may emit stale frames; read until one matches this command.
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "no matching ESP response"));
        }
        let frame = read_frame(ch, remaining)?;
        if frame.len() >= 2 && frame[0] == DIR_RESP && frame[1] == cmd {
            return parse_response(cmd, &frame);
        }
    }
}

fn sync_payload() -> Vec<u8> {
    let mut d = vec![0x07, 0x07, 0x12, 0x20];
    d.extend(std::iter::repeat(0x55u8).take(32));
    d
}

pub fn sync(ch: &mut dyn ByteChannel, running: &AtomicBool) -> io::Result<()> {
    let payload = sync_payload();
    let mut last_err = other("no attempts");
    for _ in 0..7 {
        if !running.load(Ordering::SeqCst) {
            return Err(other("interrupted"));
        }
        match command(ch, CMD_SYNC, &payload, Duration::from_millis(500)) {
            Ok(_) => return Ok(()),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

pub fn read_reg(ch: &mut dyn ByteChannel, addr: u32, running: &AtomicBool) -> io::Result<u32> {
    if !running.load(Ordering::SeqCst) {
        return Err(other("interrupted"));
    }
    let (value, _) = command(ch, CMD_READ_REG, &addr.to_le_bytes(), Duration::from_secs(2))?;
    Ok(value)
}

pub enum EspOp {
    Sync,
    ReadReg(u32),
}

pub fn esp_flow(port: &str, baud: u32, op: EspOp, running: Arc<AtomicBool>) -> Result<(), Box<dyn Error>> {
    println!("\n{}", "=== ESP ROM (UART download mode) ===".bold().magenta());
    println!("{} {} @ {} baud", "Target:".cyan(), port, baud);

    let mut p = serialport::new(port, baud)
        .timeout(Duration::from_millis(200))
        .open()
        .map_err(|e| format!("open {}: {}", port, e))?;

    // esptool classic download reset: hold EN low, pull IO0 low, release EN
    // with IO0 still low so the ROM enters UART download mode.
    p.write_data_terminal_ready(false)?;
    p.write_request_to_send(true)?;
    sleep(Duration::from_millis(100));
    p.write_data_terminal_ready(true)?;
    p.write_request_to_send(false)?;
    sleep(Duration::from_millis(50));
    p.write_data_terminal_ready(false)?;
    sleep(Duration::from_millis(100));
    p.clear(serialport::ClearBuffer::All).ok();
    println!("{} download-mode reset sent, syncing...", "[*]".bold().yellow());

    let mut ch = SerialChannel::new(&mut *p);
    sync(&mut ch, &running).map_err(|e| -> Box<dyn Error> {
        format!(
            "SYNC failed: {} (is the board in download mode? hold GPIO0/FLASH during reset, check baud)",
            e
        )
        .into()
    })?;
    ui::win("ESP ROM DOWNLOAD MODE", "chip answered SYNC");

    if let EspOp::ReadReg(addr) = op {
        let v = read_reg(&mut ch, addr, &running)?;
        ui::found(&format!("reg {:#010x} = {:#010x}", addr, v));
    }
    Ok(())
}

use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xfer::ByteChannel;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::AtomicBool;
    use std::thread;

    #[test]
    fn slip_encode_escapes_delimiters() {
        // A payload containing END and ESC must be escaped, framed by END.
        let enc = slip_encode(&[0x01, SLIP_END, SLIP_ESC, 0x02]);
        assert_eq!(
            enc,
            vec![
                SLIP_END, 0x01, SLIP_ESC, SLIP_ESC_END, SLIP_ESC, SLIP_ESC_ESC, 0x02, SLIP_END
            ]
        );
    }

    #[test]
    fn request_packet_layout() {
        // READ_REG of 0x3ff00050: dir 0, cmd 0x0a, size 4, checksum 0, addr LE.
        let req = build_request(CMD_READ_REG, &0x3ff0_0050u32.to_le_bytes());
        assert_eq!(&req[..8], &[0x00, 0x0a, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(&req[8..], &[0x50, 0x00, 0xf0, 0x3f]);
    }

    struct SockChan(UnixStream);
    impl ByteChannel for SockChan {
        fn read_byte(&mut self, timeout: Duration) -> io::Result<Option<u8>> {
            self.0.set_read_timeout(Some(timeout))?;
            let mut b = [0u8; 1];
            match self.0.read(&mut b) {
                Ok(1) => Ok(Some(b[0])),
                Ok(_) => Ok(None),
                Err(ref e)
                    if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) =>
                {
                    Ok(None)
                }
                Err(e) => Err(e),
            }
        }
        fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            Write::write_all(&mut self.0, buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Write::flush(&mut self.0)
        }
    }

    fn mock_rom(mut s: UnixStream, reg_value: u32) {
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 512];
        // Read one SLIP frame from the client.
        let mut frame = Vec::new();
        let mut started = false;
        loop {
            let n = match s.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            for &b in &buf[..n] {
                if b == SLIP_END {
                    if started && !frame.is_empty() {
                        started = false;
                        // Unescape and dispatch.
                        let req = unescape(&frame);
                        respond(&mut s, &req, reg_value);
                        return;
                    }
                    started = true;
                    frame.clear();
                } else if started {
                    frame.push(b);
                }
            }
        }
    }

    fn unescape(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == SLIP_ESC && i + 1 < b.len() {
                out.push(if b[i + 1] == SLIP_ESC_END { SLIP_END } else { SLIP_ESC });
                i += 2;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        out
    }

    fn respond(s: &mut UnixStream, req: &[u8], reg_value: u32) {
        let cmd = req[1];
        let mut payload = vec![DIR_RESP, cmd];
        payload.extend_from_slice(&2u16.to_le_bytes()); // size = 2 status bytes
        let value = if cmd == CMD_READ_REG { reg_value } else { 0 };
        payload.extend_from_slice(&value.to_le_bytes());
        payload.extend_from_slice(&[0x00, 0x00]); // status OK
        s.write_all(&slip_encode(&payload)).unwrap();
        s.flush().unwrap();
    }

    #[test]
    fn sync_handshake_over_mock_rom() {
        let (a, b) = UnixStream::pair().unwrap();
        let h = thread::spawn(move || mock_rom(b, 0));
        let running = AtomicBool::new(true);
        let mut ch = SockChan(a);
        assert!(sync(&mut ch, &running).is_ok());
        h.join().unwrap();
    }

    #[test]
    fn read_reg_over_mock_rom() {
        let (a, b) = UnixStream::pair().unwrap();
        let h = thread::spawn(move || mock_rom(b, 0x00f0_1d83)); // ESP32 magic, as a value
        let running = AtomicBool::new(true);
        let mut ch = SockChan(a);
        let v = read_reg(&mut ch, 0x4000_1000, &running).unwrap();
        assert_eq!(v, 0x00f0_1d83);
        h.join().unwrap();
    }
}
