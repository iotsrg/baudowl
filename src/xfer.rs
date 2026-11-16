use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const SOH: u8 = 0x01; // 128-byte block header
const STX: u8 = 0x02; // 1024-byte block header
const EOT: u8 = 0x04; // end of transmission
const ACK: u8 = 0x06;
const NAK: u8 = 0x15;
const CAN: u8 = 0x18;
const CRC_C: u8 = b'C'; // receiver requests CRC mode / next batch
const PAD: u8 = 0x1a; // CTRL-Z pad for the final short block

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XferMode {
    Xmodem,
    Xmodem1k,
    Ymodem,
}

impl XferMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "xmodem" | "x" => Some(Self::Xmodem),
            "xmodem1k" | "x1k" | "1k" => Some(Self::Xmodem1k),
            "ymodem" | "y" => Some(Self::Ymodem),
            _ => None,
        }
    }
    pub fn uboot_cmd(&self, addr: u64) -> String {
        match self {
            Self::Xmodem | Self::Xmodem1k => format!("loadx {:#x}", addr),
            Self::Ymodem => format!("loady {:#x}", addr),
        }
    }
}

pub trait ByteChannel {
    fn read_byte(&mut self, timeout: Duration) -> io::Result<Option<u8>>;
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
}

pub fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

fn checksum8(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |a, &b| a.wrapping_add(b))
}

fn frame_block(block: u8, payload: &[u8], use_crc: bool) -> Vec<u8> {
    let header = if payload.len() == 1024 { STX } else { SOH };
    let mut pkt = Vec::with_capacity(payload.len() + 5);
    pkt.push(header);
    pkt.push(block);
    pkt.push(255 - block);
    pkt.extend_from_slice(payload);
    if use_crc {
        pkt.extend_from_slice(&crc16_xmodem(payload).to_be_bytes());
    } else {
        pkt.push(checksum8(payload));
    }
    pkt
}

fn padded(chunk: &[u8], size: usize) -> Vec<u8> {
    let mut b = vec![PAD; size];
    b[..chunk.len()].copy_from_slice(chunk);
    b
}

fn wait_start(ch: &mut dyn ByteChannel, running: &AtomicBool) -> io::Result<bool> {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if !running.load(Ordering::SeqCst) {
            return Err(other("interrupted before transfer started"));
        }
        match ch.read_byte(Duration::from_millis(500))? {
            Some(CRC_C) => return Ok(true),
            Some(NAK) => return Ok(false),
            Some(CAN) => return Err(other("receiver cancelled before start")),
            _ => {}
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "receiver never sent C/NAK (is loadx/loady running on the device?)",
    ))
}

fn send_block(
    ch: &mut dyn ByteChannel,
    block: u8,
    payload: &[u8],
    use_crc: bool,
    running: &AtomicBool,
) -> io::Result<()> {
    let pkt = frame_block(block, payload, use_crc);
    for _ in 0..10 {
        if !running.load(Ordering::SeqCst) {
            return Err(other("interrupted mid-transfer"));
        }
        ch.write_all(&pkt)?;
        ch.flush()?;
        match ch.read_byte(Duration::from_secs(10))? {
            Some(ACK) => return Ok(()),
            Some(CAN) => return Err(other("receiver cancelled")),
            // NAK, stray 'C', or timeout -> retransmit
            _ => {}
        }
    }
    Err(other("too many retries sending a block"))
}

fn send_eot(ch: &mut dyn ByteChannel) -> io::Result<()> {
    for _ in 0..6 {
        ch.write_all(&[EOT])?;
        ch.flush()?;
        // The receiver NAKs the first EOT by convention, so resend on anything
        // that is not an ACK.
        if let Some(ACK) = ch.read_byte(Duration::from_secs(5))? {
            return Ok(());
        }
    }
    Err(other("no ACK for EOT"))
}

fn send_data(
    ch: &mut dyn ByteChannel,
    data: &[u8],
    mode: XferMode,
    use_crc: bool,
    running: &AtomicBool,
) -> io::Result<()> {
    let mut block: u8 = 1;
    let mut off = 0usize;
    while off < data.len() {
        let remaining = data.len() - off;
        let size = if mode == XferMode::Xmodem {
            128
        } else if remaining >= 1024 {
            1024
        } else {
            128
        };
        let take = remaining.min(size);
        let payload = padded(&data[off..off + take], size);
        send_block(ch, block, &payload, use_crc, running)?;
        block = block.wrapping_add(1);
        off += take;
    }
    Ok(())
}

fn ymodem_header(filename: &str, size: u64) -> Vec<u8> {
    let mut b = vec![0u8; 128];
    let name = filename.as_bytes();
    let n = name.len().min(100);
    b[..n].copy_from_slice(&name[..n]);
    // field separator is the NUL already in place at b[n]; size follows.
    let meta = format!("{}", size);
    let start = n + 1;
    let m = meta.len().min(128 - start - 1);
    b[start..start + m].copy_from_slice(&meta.as_bytes()[..m]);
    b
}

pub fn send(
    ch: &mut dyn ByteChannel,
    data: &[u8],
    mode: XferMode,
    filename: &str,
    running: &AtomicBool,
) -> io::Result<u64> {
    if mode == XferMode::Ymodem {
        // Header block (block 0), always CRC in YMODEM.
        wait_start(ch, running)?;
        let header = ymodem_header(filename, data.len() as u64);
        send_block(ch, 0, &header, true, running)?;
        // Receiver sends 'C' again to begin the data stream.
        wait_start(ch, running)?;
        send_data(ch, data, mode, true, running)?;
        send_eot(ch)?;
        // Closing null block ends the batch.
        wait_start(ch, running)?;
        send_block(ch, 0, &[0u8; 128], true, running)?;
    } else {
        let use_crc = wait_start(ch, running)?;
        send_data(ch, data, mode, use_crc, running)?;
        send_eot(ch)?;
    }
    Ok(data.len() as u64)
}

fn other<E: Into<Box<dyn std::error::Error + Send + Sync>>>(msg: E) -> io::Error {
    // io::Error::other needs Rust 1.74; keep the MSRV at 1.63.
    io::Error::new(io::ErrorKind::Other, msg)
}

pub struct SerialChannel<'a> {
    port: &'a mut dyn serialport::SerialPort,
}

impl<'a> SerialChannel<'a> {
    pub fn new(port: &'a mut dyn serialport::SerialPort) -> Self {
        Self { port }
    }
}

impl ByteChannel for SerialChannel<'_> {
    fn read_byte(&mut self, timeout: Duration) -> io::Result<Option<u8>> {
        self.port.set_timeout(timeout)?;
        let mut b = [0u8; 1];
        match self.port.read(&mut b) {
            Ok(1) => Ok(Some(b[0])),
            Ok(_) => Ok(None),
            Err(ref e) if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        Write::write_all(&mut self.port, buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Write::flush(&mut self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn crc16_xmodem_reference_vector() {
        // Canonical XMODEM CRC of "123456789" is 0x31C3.
        assert_eq!(crc16_xmodem(b"123456789"), 0x31C3);
        assert_eq!(crc16_xmodem(&[]), 0x0000);
    }

    #[test]
    fn frame_block_layout() {
        let pkt = frame_block(1, &[0u8; 128], true);
        assert_eq!(pkt[0], SOH);
        assert_eq!(pkt[1], 1);
        assert_eq!(pkt[2], 254);
        assert_eq!(pkt.len(), 1 + 1 + 1 + 128 + 2);
        let big = frame_block(2, &[0u8; 1024], false);
        assert_eq!(big[0], STX);
        assert_eq!(big.len(), 1 + 1 + 1 + 1024 + 1); // checksum is 1 byte
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

    fn recv(stream: UnixStream, ymodem: bool) -> Vec<u8> {
        let mut s = stream;
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut out = Vec::new();
        let read_exact = |s: &mut UnixStream, n: usize| -> Option<Vec<u8>> {
            let mut v = vec![0u8; n];
            let mut got = 0;
            while got < n {
                match s.read(&mut v[got..]) {
                    Ok(0) => return None,
                    Ok(k) => got += k,
                    Err(_) => return None,
                }
            }
            Some(v)
        };
        let mut batches_expected = if ymodem { 2u8 } else { 1u8 }; // header 'C' + data 'C'
        // Kick off: request CRC mode.
        s.write_all(&[CRC_C]).unwrap();
        loop {
            let mut h = [0u8; 1];
            if !matches!(s.read(&mut h), Ok(1)) {
                break;
            }
            match h[0] {
                SOH | STX => {
                    let len = if h[0] == STX { 1024 } else { 128 };
                    let meta = match read_exact(&mut s, 2) {
                        Some(m) => m,
                        None => break,
                    };
                    let block = meta[0];
                    let data = read_exact(&mut s, len).unwrap();
                    let _crc = read_exact(&mut s, 2).unwrap();
                    let expect = crc16_xmodem(&data).to_be_bytes();
                    if _crc != expect {
                        s.write_all(&[NAK]).unwrap();
                        continue;
                    }
                    s.write_all(&[ACK]).unwrap();
                    if ymodem && block == 0 {
                        // header or closing block; after the header send another
                        // 'C', after the closing null block the batch is done.
                        batches_expected = batches_expected.saturating_sub(1);
                        if batches_expected == 0 {
                            break;
                        }
                        s.write_all(&[CRC_C]).unwrap();
                        continue;
                    }
                    out.extend_from_slice(&data);
                }
                EOT => {
                    s.write_all(&[ACK]).unwrap();
                    if ymodem {
                        // expect the closing null block; prompt for it
                        s.write_all(&[CRC_C]).unwrap();
                    } else {
                        break;
                    }
                }
                _ => {}
            }
        }
        out
    }

    fn roundtrip(mode: XferMode, len: usize) {
        let (a, b) = UnixStream::pair().unwrap();
        let payload: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
        let ymodem = mode == XferMode::Ymodem;
        let p2 = payload.clone();
        let rx = thread::spawn(move || recv(b, ymodem));
        let running = Arc::new(AtomicBool::new(true));
        let mut ch = SockChan(a);
        let sent = send(&mut ch, &p2, mode, "fw.bin", &running).unwrap();
        assert_eq!(sent, len as u64);
        let got = rx.join().unwrap();
        assert!(got.len() >= len, "receiver got {} bytes for {}", got.len(), len);
        assert_eq!(&got[..len], &payload[..], "payload mismatch for {:?}", mode);
    }

    #[test]
    fn xmodem_roundtrip() {
        roundtrip(XferMode::Xmodem, 300); // 3 x 128 blocks, last padded
    }

    #[test]
    fn xmodem1k_roundtrip() {
        roundtrip(XferMode::Xmodem1k, 1024 + 200); // one 1k block + a 128 tail
    }

    #[test]
    fn ymodem_roundtrip() {
        roundtrip(XferMode::Ymodem, 1500); // header + 1k + 128 tail + close
    }
}
