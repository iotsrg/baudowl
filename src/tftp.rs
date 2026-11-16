use std::fs::File;
use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const OP_RRQ: u16 = 1;
const OP_WRQ: u16 = 2;
const OP_DATA: u16 = 3;
const OP_ACK: u16 = 4;
const OP_ERROR: u16 = 5;

const BUF: usize = 2048;

fn other<E: Into<Box<dyn std::error::Error + Send + Sync>>>(msg: E) -> io::Error {
    // io::Error::other needs Rust 1.74; this keeps the MSRV at 1.63.
    io::Error::new(io::ErrorKind::Other, msg)
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

fn ack(block: u16) -> [u8; 4] {
    let mut p = [0u8; 4];
    p[0..2].copy_from_slice(&OP_ACK.to_be_bytes());
    p[2..4].copy_from_slice(&block.to_be_bytes());
    p
}

fn error_packet(code: u16, msg: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + msg.len());
    v.extend_from_slice(&OP_ERROR.to_be_bytes());
    v.extend_from_slice(&code.to_be_bytes());
    v.extend_from_slice(msg.as_bytes());
    v.push(0);
    v
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn opcode(b: &[u8]) -> Option<u16> {
    if b.len() >= 2 {
        Some(u16::from_be_bytes([b[0], b[1]]))
    } else {
        None
    }
}

pub fn serve_wrq(
    sock: &UdpSocket,
    out_path: &str,
    running: &AtomicBool,
    first_wait: Duration,
    block_wait: Duration,
    max_bytes: u64,
) -> io::Result<u64> {
    sock.set_read_timeout(Some(Duration::from_millis(400)))?;
    let mut buf = [0u8; BUF];

    // Phase 1: wait for the write request and lock onto the sender's TID.
    let deadline = Instant::now() + first_wait;
    let peer: SocketAddr = loop {
        if !running.load(Ordering::SeqCst) {
            return Err(other("interrupted before TFTP transfer began"));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no TFTP write request from device within the wait window",
            ));
        }
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => match opcode(&buf[..n]) {
                Some(OP_WRQ) => {
                    let name = cstr(&buf[2..n]);
                    sock.send_to(&ack(0), from)?;
                    let _ = name; // filename is cosmetic; we write to out_path
                    break from;
                }
                Some(OP_RRQ) => {
                    let _ = sock.send_to(&error_packet(4, "baudowl only receives (WRQ)"), from);
                }
                _ => {}
            },
            Err(ref e) if is_timeout(e) => {}
            Err(e) => return Err(e),
        }
    };

    // Phase 2: DATA/ACK until a short (< 512-byte) block ends the transfer.
    sock.set_read_timeout(Some(block_wait))?;
    let mut file = File::create(out_path)?;
    let mut expected: u32 = 1;
    let mut total: u64 = 0;
    let mut last_ack = ack(0);
    let mut stalls: u32 = 0;

    loop {
        if !running.load(Ordering::SeqCst) {
            return Err(other("interrupted mid-transfer"));
        }
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                if from != peer || n < 4 {
                    continue; // wrong TID or too short to be DATA
                }
                let op = match opcode(&buf[..n]) {
                    Some(o) => o,
                    None => continue,
                };
                if op == OP_ERROR {
                    return Err(other(format!("device TFTP error: {}", cstr(&buf[4..n]))));
                }
                if op != OP_DATA {
                    continue;
                }
                let block = u16::from_be_bytes([buf[2], buf[3]]);
                let data = &buf[4..n];
                let want = (expected & 0xffff) as u16;
                if block == want {
                    if total + data.len() as u64 > max_bytes {
                        let _ = sock.send_to(&error_packet(3, "exceeds expected size"), peer);
                        return Err(other("transfer exceeded expected length; aborting"));
                    }
                    file.write_all(data)?;
                    total += data.len() as u64;
                    last_ack = ack(block);
                    sock.send_to(&last_ack, peer)?;
                    expected += 1;
                    stalls = 0;
                    if data.len() < 512 {
                        break; // final (short) block
                    }
                } else if block == want.wrapping_sub(1) {
                    // Retransmit of the block we already stored: re-ACK, do not rewrite.
                    let _ = sock.send_to(&ack(block), peer);
                }
                // Any other block number is out of sequence; ignore it.
            }
            Err(ref e) if is_timeout(e) => {
                stalls += 1;
                if stalls > 6 {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TFTP transfer stalled (no data)",
                    ));
                }
                let _ = sock.send_to(&last_ack, peer); // nudge the sender
            }
            Err(e) => return Err(e),
        }
    }

    file.flush()?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn packet_builders_match_rfc1350() {
        // ACK block 1 = 00 04 00 01
        assert_eq!(ack(1), [0x00, 0x04, 0x00, 0x01]);
        assert_eq!(ack(0x0102), [0x00, 0x04, 0x01, 0x02]);
        // ERROR code 4 "no": 00 05 00 04 6e 6f 00
        assert_eq!(error_packet(4, "no"), vec![0, 5, 0, 4, b'n', b'o', 0]);
        assert_eq!(cstr(b"fw.bin\0octet\0"), "fw.bin");
        assert_eq!(opcode(&[0, 2, 9]), Some(OP_WRQ));
    }

    #[test]
    fn receives_a_full_upload_over_loopback() {
        let dir = std::env::temp_dir();
        let out = dir.join(format!("baudowl_tftp_test_{}.bin", std::process::id()));
        let out_path = out.to_string_lossy().into_owned();

        // Payload spanning several blocks with a short final block (1100 bytes
        // = 512 + 512 + 76), so the terminating-block logic is exercised.
        let payload: Vec<u8> = (0..1100u32).map(|i| (i * 7 + 3) as u8).collect();

        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let running = Arc::new(AtomicBool::new(true));

        let op = out_path.clone();
        let r = running.clone();
        let handle = thread::spawn(move || {
            serve_wrq(
                &server,
                &op,
                &r,
                Duration::from_secs(5),
                Duration::from_secs(2),
                4096,
            )
        });

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // WRQ: opcode 2, "fw.bin", 0, "octet", 0
        let mut wrq = vec![0u8, 2];
        wrq.extend_from_slice(b"fw.bin\0octet\0");
        client.send_to(&wrq, server_addr).unwrap();

        let mut buf = [0u8; 2048];
        // Expect ACK block 0; the reply comes from the server's TID.
        let (n, srv) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0, 4, 0, 0], "server must ACK block 0");

        let mut block: u16 = 1;
        for chunk in payload.chunks(512) {
            let mut data = Vec::with_capacity(4 + chunk.len());
            data.extend_from_slice(&OP_DATA.to_be_bytes());
            data.extend_from_slice(&block.to_be_bytes());
            data.extend_from_slice(chunk);
            client.send_to(&data, srv).unwrap();
            let (an, _) = client.recv_from(&mut buf).unwrap();
            assert_eq!(
                &buf[..an],
                &[0, 4, (block >> 8) as u8, block as u8],
                "server must ACK data block {}",
                block
            );
            block += 1;
        }

        let received = handle.join().unwrap().expect("serve_wrq should succeed");
        assert_eq!(received, payload.len() as u64);
        let written = std::fs::read(&out_path).unwrap();
        assert_eq!(written, payload, "written bytes must match the upload exactly");
        let _ = std::fs::remove_file(&out_path);
    }
}
