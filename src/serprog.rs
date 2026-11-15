//! serprog (Serial Programmer) protocol client for direct SPI flash access.
//!
//! Implements the flashrom serprog protocol, allowing baudowl to talk to
//! serprog-compatible programmers (CH341A, Bus Pirate, Arduino, ESP32, etc.)
//! over UART. This gives baudowl direct flash read/write/erase/verify without
//! needing flashrom installed.
//!
//! Protocol reference: flashrom source, include/programmer.h (serprog opcodes).

use std::error::Error;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use colored::*;

use crate::ui;
use crate::xfer::ByteChannel;

// ── serprog protocol constants ──────────────────────────────────────────

const ACK: u8 = 0x06;
const NAK: u8 = 0x15;

#[allow(dead_code)]
const S_CMD_NOP: u8 = 0x00;
const S_CMD_Q_IFACE: u8 = 0x01;
const S_CMD_Q_CMDMAP: u8 = 0x02;
const S_CMD_Q_PGMNAME: u8 = 0x03;
const S_CMD_Q_SERBUF: u8 = 0x04;
const S_CMD_Q_BUSTYPE: u8 = 0x05;
#[allow(dead_code)]
const S_CMD_Q_OPBUF: u8 = 0x07;
#[allow(dead_code)]
const S_CMD_Q_WRNMAXLEN: u8 = 0x08;
const S_CMD_SYNCNOP: u8 = 0x10;
const S_CMD_Q_RDNMAXLEN: u8 = 0x11;
const S_CMD_S_BUSTYPE: u8 = 0x12;
const S_CMD_O_SPIOP: u8 = 0x13;

const BUS_SPI: u8 = 0x08;

// ── SPI flash command bytes ─────────────────────────────────────────────

const SPI_RDID: u8 = 0x9f;
const SPI_READ: u8 = 0x03;
const SPI_RDSR: u8 = 0x05;
const SPI_WREN: u8 = 0x06;
const SPI_PP: u8 = 0x02;
const SPI_SE_4K: u8 = 0x20;
const SPI_CE: u8 = 0xc7;

const SR_BUSY: u8 = 0x01;
const PAGE_SIZE: u32 = 256;
const SECTOR_SIZE: u32 = 4096;

// ── chip database ───────────────────────────────────────────────────────

const MB: u32 = 1024 * 1024;

pub struct ChipInfo {
    pub jedec: [u8; 3],
    pub name: &'static str,
    pub size: u32,
}

const CHIP_DB: &[ChipInfo] = &[
    ChipInfo { jedec: [0xEF, 0x40, 0x14], name: "Winbond W25Q80", size: MB },
    ChipInfo { jedec: [0xEF, 0x40, 0x15], name: "Winbond W25Q16", size: 2 * MB },
    ChipInfo { jedec: [0xEF, 0x40, 0x16], name: "Winbond W25Q32", size: 4 * MB },
    ChipInfo { jedec: [0xEF, 0x40, 0x17], name: "Winbond W25Q64", size: 8 * MB },
    ChipInfo { jedec: [0xEF, 0x40, 0x18], name: "Winbond W25Q128", size: 16 * MB },
    ChipInfo { jedec: [0xC2, 0x20, 0x16], name: "Macronix MX25L3206E", size: 4 * MB },
    ChipInfo { jedec: [0xC2, 0x20, 0x17], name: "Macronix MX25L6406E", size: 8 * MB },
    ChipInfo { jedec: [0xC2, 0x20, 0x18], name: "Macronix MX25L12835F", size: 16 * MB },
    ChipInfo { jedec: [0xC8, 0x40, 0x15], name: "GigaDevice GD25Q16", size: 2 * MB },
    ChipInfo { jedec: [0xC8, 0x40, 0x16], name: "GigaDevice GD25Q32", size: 4 * MB },
    ChipInfo { jedec: [0xC8, 0x40, 0x17], name: "GigaDevice GD25Q64", size: 8 * MB },
    ChipInfo { jedec: [0xC8, 0x40, 0x18], name: "GigaDevice GD25Q128", size: 16 * MB },
    ChipInfo { jedec: [0x9D, 0x60, 0x16], name: "ISSI IS25LP032", size: 4 * MB },
    ChipInfo { jedec: [0x9D, 0x60, 0x17], name: "ISSI IS25LP064", size: 8 * MB },
    ChipInfo { jedec: [0x01, 0x60, 0x17], name: "Spansion S25FL064L", size: 8 * MB },
    ChipInfo { jedec: [0x01, 0x60, 0x18], name: "Spansion S25FL128L", size: 16 * MB },
    ChipInfo { jedec: [0x1C, 0x70, 0x16], name: "EON EN25QH32", size: 4 * MB },
    ChipInfo { jedec: [0x1C, 0x70, 0x17], name: "EON EN25QH64", size: 8 * MB },
    ChipInfo { jedec: [0x20, 0x40, 0x16], name: "XMC XM25QH32B", size: 4 * MB },
    ChipInfo { jedec: [0x5E, 0x40, 0x16], name: "Zbit ZB25VQ32", size: 4 * MB },
    ChipInfo { jedec: [0xBF, 0x25, 0x41], name: "SST SST25VF016B", size: 2 * MB },
    ChipInfo { jedec: [0x1F, 0x86, 0x01], name: "Adesto AT25SF161", size: 2 * MB },
    ChipInfo { jedec: [0x68, 0x40, 0x17], name: "Boya BY25Q64AS", size: 8 * MB },
    ChipInfo { jedec: [0x85, 0x60, 0x16], name: "Puya P25Q32H", size: 4 * MB },
];

fn lookup_chip(jedec: &[u8; 3]) -> Option<&'static ChipInfo> {
    CHIP_DB.iter().find(|c| &c.jedec == jedec)
}

fn guess_size_from_capacity_byte(cap: u8) -> Option<u32> {
    if cap >= 0x12 && cap <= 0x19 {
        Some(1u32 << cap)
    } else {
        None
    }
}

fn manufacturer_name(id: u8) -> &'static str {
    match id {
        0xEF => "Winbond",
        0xC2 => "Macronix",
        0xC8 => "GigaDevice",
        0x9D => "ISSI",
        0x01 => "Spansion/Infineon",
        0xBF => "SST/Microchip",
        0x1C => "EON",
        0x20 => "XMC/XTX",
        0x5E => "Zbit",
        0x1F => "Adesto/Atmel",
        0x68 => "Boya",
        0x85 => "Puya",
        0x37 => "AMIC",
        _ => "Unknown",
    }
}

// ── transport helpers ───────────────────────────────────────────────────

fn read_exact(ch: &mut dyn ByteChannel, n: usize, timeout: Duration) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut buf = Vec::with_capacity(n);
    while buf.len() < n {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("serprog: got {}/{} bytes before timeout", buf.len(), n),
            ));
        }
        let per_byte = remaining.min(Duration::from_millis(500));
        if let Some(b) = ch.read_byte(per_byte)? {
            buf.push(b);
        }
    }
    Ok(buf)
}

fn expect_ack(ch: &mut dyn ByteChannel, context: &str) -> io::Result<()> {
    let b = read_exact(ch, 1, Duration::from_secs(3))?;
    if b[0] != ACK {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("{}: expected ACK (0x06), got {:#04x}", context, b[0]),
        ));
    }
    Ok(())
}

fn cmd_resp(ch: &mut dyn ByteChannel, cmd: u8, resp_len: usize) -> io::Result<Vec<u8>> {
    ch.write_all(&[cmd])?;
    ch.flush()?;
    expect_ack(ch, &format!("cmd {:#04x}", cmd))?;
    if resp_len > 0 {
        read_exact(ch, resp_len, Duration::from_secs(3))
    } else {
        Ok(Vec::new())
    }
}

fn cmd_supported(cmdmap: &[u8; 32], cmd: u8) -> bool {
    let byte = (cmd / 8) as usize;
    let bit = cmd % 8;
    byte < 32 && (cmdmap[byte] & (1 << bit)) != 0
}

// ── serprog protocol layer ──────────────────────────────────────────────

fn sync_nop(ch: &mut dyn ByteChannel) -> io::Result<()> {
    ch.write_all(&[S_CMD_SYNCNOP])?;
    ch.flush()?;
    let resp = read_exact(ch, 2, Duration::from_secs(3))?;
    if resp[0] != NAK || resp[1] != ACK {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("SYNCNOP: expected NAK+ACK, got {:#04x} {:#04x}", resp[0], resp[1]),
        ));
    }
    Ok(())
}

fn query_iface(ch: &mut dyn ByteChannel) -> io::Result<u16> {
    let r = cmd_resp(ch, S_CMD_Q_IFACE, 2)?;
    Ok(u16::from_le_bytes([r[0], r[1]]))
}

fn query_cmdmap(ch: &mut dyn ByteChannel) -> io::Result<[u8; 32]> {
    let r = cmd_resp(ch, S_CMD_Q_CMDMAP, 32)?;
    let mut map = [0u8; 32];
    map.copy_from_slice(&r);
    Ok(map)
}

fn query_pgmname(ch: &mut dyn ByteChannel) -> io::Result<String> {
    let r = cmd_resp(ch, S_CMD_Q_PGMNAME, 16)?;
    let end = r.iter().position(|&b| b == 0).unwrap_or(16);
    Ok(String::from_utf8_lossy(&r[..end]).to_string())
}

fn query_bustype(ch: &mut dyn ByteChannel) -> io::Result<u8> {
    let r = cmd_resp(ch, S_CMD_Q_BUSTYPE, 1)?;
    Ok(r[0])
}

fn query_serbuf(ch: &mut dyn ByteChannel) -> io::Result<u16> {
    let r = cmd_resp(ch, S_CMD_Q_SERBUF, 2)?;
    Ok(u16::from_le_bytes([r[0], r[1]]))
}

fn query_rdnmaxlen(ch: &mut dyn ByteChannel) -> io::Result<u32> {
    let r = cmd_resp(ch, S_CMD_Q_RDNMAXLEN, 3)?;
    Ok(u32::from_le_bytes([r[0], r[1], r[2], 0]))
}

fn set_bustype(ch: &mut dyn ByteChannel, bus: u8) -> io::Result<()> {
    ch.write_all(&[S_CMD_S_BUSTYPE, bus])?;
    ch.flush()?;
    expect_ack(ch, "S_BUSTYPE")
}

pub struct ProgrammerCaps {
    pub name: String,
    #[allow(dead_code)]
    pub cmdmap: [u8; 32],
    pub serbuf: u16,
    pub max_read: u32,
}

fn handshake(ch: &mut dyn ByteChannel) -> io::Result<ProgrammerCaps> {
    sync_nop(ch)?;
    let ver = query_iface(ch)?;
    if ver != 1 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("unsupported serprog interface version {}", ver),
        ));
    }
    let cmdmap = query_cmdmap(ch)?;
    if !cmd_supported(&cmdmap, S_CMD_O_SPIOP) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "programmer does not support SPI operations (S_CMD_O_SPIOP)",
        ));
    }
    let name = if cmd_supported(&cmdmap, S_CMD_Q_PGMNAME) {
        query_pgmname(ch)?
    } else {
        "(unknown)".into()
    };
    let bustype = query_bustype(ch)?;
    if bustype & BUS_SPI == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "programmer does not support SPI bus",
        ));
    }
    set_bustype(ch, BUS_SPI)?;

    let serbuf = if cmd_supported(&cmdmap, S_CMD_Q_SERBUF) {
        query_serbuf(ch)?
    } else {
        256
    };
    let max_read = if cmd_supported(&cmdmap, S_CMD_Q_RDNMAXLEN) {
        query_rdnmaxlen(ch)?
    } else {
        0
    };
    Ok(ProgrammerCaps { name, cmdmap, serbuf, max_read })
}

fn read_chunk_size(caps: &ProgrammerCaps) -> usize {
    let from_maxread = if caps.max_read > 0 { caps.max_read as usize } else { usize::MAX };
    let from_serbuf = (caps.serbuf as usize).saturating_sub(8);
    from_maxread.min(from_serbuf).min(4096).max(64)
}

// ── SPI operations (via serprog SPIOP) ──────────────────────────────────

fn spi_op(
    ch: &mut dyn ByteChannel,
    sdata: &[u8],
    rlen: u32,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let slen = sdata.len() as u32;
    let mut pkt = Vec::with_capacity(7 + sdata.len());
    pkt.push(S_CMD_O_SPIOP);
    pkt.push((slen & 0xff) as u8);
    pkt.push(((slen >> 8) & 0xff) as u8);
    pkt.push(((slen >> 16) & 0xff) as u8);
    pkt.push((rlen & 0xff) as u8);
    pkt.push(((rlen >> 8) & 0xff) as u8);
    pkt.push(((rlen >> 16) & 0xff) as u8);
    pkt.extend_from_slice(sdata);
    ch.write_all(&pkt)?;
    ch.flush()?;
    expect_ack(ch, "SPIOP")?;
    if rlen > 0 {
        read_exact(ch, rlen as usize, timeout)
    } else {
        Ok(Vec::new())
    }
}

fn read_jedec_id(ch: &mut dyn ByteChannel) -> io::Result<[u8; 3]> {
    let r = spi_op(ch, &[SPI_RDID], 3, Duration::from_secs(2))?;
    Ok([r[0], r[1], r[2]])
}

fn read_status(ch: &mut dyn ByteChannel) -> io::Result<u8> {
    let r = spi_op(ch, &[SPI_RDSR], 1, Duration::from_secs(2))?;
    Ok(r[0])
}

fn wait_ready(
    ch: &mut dyn ByteChannel,
    timeout: Duration,
    running: &AtomicBool,
) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if !running.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted"));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "flash BUSY timeout"));
        }
        let sr = read_status(ch)?;
        if sr & SR_BUSY == 0 {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn write_enable(ch: &mut dyn ByteChannel) -> io::Result<()> {
    spi_op(ch, &[SPI_WREN], 0, Duration::from_secs(2))?;
    Ok(())
}

fn read_flash_chunk(ch: &mut dyn ByteChannel, addr: u32, len: u32) -> io::Result<Vec<u8>> {
    let cmd = [
        SPI_READ,
        ((addr >> 16) & 0xff) as u8,
        ((addr >> 8) & 0xff) as u8,
        (addr & 0xff) as u8,
    ];
    let timeout = Duration::from_secs(2 + (len as u64 / 500));
    spi_op(ch, &cmd, len, timeout)
}

fn page_program(
    ch: &mut dyn ByteChannel,
    addr: u32,
    data: &[u8],
    running: &AtomicBool,
) -> io::Result<()> {
    write_enable(ch)?;
    let mut cmd = Vec::with_capacity(4 + data.len());
    cmd.push(SPI_PP);
    cmd.push(((addr >> 16) & 0xff) as u8);
    cmd.push(((addr >> 8) & 0xff) as u8);
    cmd.push((addr & 0xff) as u8);
    cmd.extend_from_slice(data);
    spi_op(ch, &cmd, 0, Duration::from_secs(2))?;
    wait_ready(ch, Duration::from_millis(5000), running)
}

fn erase_sector_4k(
    ch: &mut dyn ByteChannel,
    addr: u32,
    running: &AtomicBool,
) -> io::Result<()> {
    write_enable(ch)?;
    let cmd = [
        SPI_SE_4K,
        ((addr >> 16) & 0xff) as u8,
        ((addr >> 8) & 0xff) as u8,
        (addr & 0xff) as u8,
    ];
    spi_op(ch, &cmd, 0, Duration::from_secs(2))?;
    wait_ready(ch, Duration::from_secs(3), running)
}

fn erase_chip(ch: &mut dyn ByteChannel, running: &AtomicBool) -> io::Result<()> {
    write_enable(ch)?;
    spi_op(ch, &[SPI_CE], 0, Duration::from_secs(2))?;
    wait_ready(ch, Duration::from_secs(300), running)
}

// ── high-level flash operations ─────────────────────────────────────────

fn identify(ch: &mut dyn ByteChannel) -> io::Result<(String, u32)> {
    let jedec = read_jedec_id(ch)?;
    if jedec == [0xff, 0xff, 0xff] || jedec == [0x00, 0x00, 0x00] {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "no flash detected (JEDEC ID = {:02x} {:02x} {:02x})",
                jedec[0], jedec[1], jedec[2]
            ),
        ));
    }
    if let Some(chip) = lookup_chip(&jedec) {
        let sr = read_status(ch).unwrap_or(0);
        ui::found(&format!(
            "{} ({} {} {}), JEDEC {:02X} {:02X} {:02X}, {} bytes, SR={:#04x}",
            chip.name,
            manufacturer_name(jedec[0]),
            format!("{:#04x}", jedec[1]),
            format!("{:#04x}", jedec[2]),
            jedec[0], jedec[1], jedec[2],
            chip.size, sr,
        ));
        Ok((chip.name.to_string(), chip.size))
    } else {
        let guessed = guess_size_from_capacity_byte(jedec[2]);
        let size = guessed.unwrap_or(0);
        let label = format!(
            "{} (unknown type {:02X} {:02X})",
            manufacturer_name(jedec[0]),
            jedec[1], jedec[2]
        );
        ui::warn(&format!(
            "chip not in database: JEDEC {:02X} {:02X} {:02X} - {}{}",
            jedec[0], jedec[1], jedec[2], label,
            if size > 0 {
                format!(", guessed size {} bytes (use --flash-size to override)", size)
            } else {
                ", cannot guess size (use --flash-size)".to_string()
            }
        ));
        Ok((label, size))
    }
}

fn read_full(
    ch: &mut dyn ByteChannel,
    chip_size: u32,
    start: u32,
    length: u32,
    out_path: &str,
    chunk: usize,
    running: &AtomicBool,
) -> io::Result<()> {
    let end = start + length;
    if end > chip_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "read range {:#x}..{:#x} exceeds chip size {:#x}",
                start, end, chip_size
            ),
        ));
    }
    ui::step("READ", &format!(
        "{:#x} bytes from flash offset {:#x}, chunk size {}",
        length, start, chunk
    ));

    let mut file = std::fs::File::create(out_path)?;
    let mut offset = start;
    let report_interval = (length / 4).max(chunk as u32);
    let mut next_report = start + report_interval;

    while offset < end {
        if !running.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted"));
        }
        let remain = (end - offset) as usize;
        let n = remain.min(chunk) as u32;
        let data = read_flash_chunk(ch, offset, n)?;
        io::Write::write_all(&mut file, &data)?;
        offset += n;
        if offset >= next_report || offset >= end {
            let pct = ((offset - start) as u64 * 100) / length as u64;
            ui::detail(&format!(
                "{:#x} / {:#x} ({}%)",
                offset - start, length, pct
            ));
            next_report += report_interval;
        }
    }
    ui::win("READ COMPLETE", &format!("{} bytes -> {}", length, out_path));
    Ok(())
}

fn write_full(
    ch: &mut dyn ByteChannel,
    chip_size: u32,
    start: u32,
    data: &[u8],
    running: &AtomicBool,
) -> io::Result<()> {
    let length = data.len() as u32;
    let end = start + length;
    if end > chip_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "write range {:#x}..{:#x} exceeds chip size {:#x}",
                start, end, chip_size
            ),
        ));
    }

    let sector_start = start & !0xFFF;
    let sector_end = (end + SECTOR_SIZE - 1) & !0xFFF;
    let n_sectors = (sector_end - sector_start) / SECTOR_SIZE;
    ui::step("ERASE", &format!("{} sectors ({:#x}..{:#x})", n_sectors, sector_start, sector_end));

    let mut addr = sector_start;
    while addr < sector_end {
        if !running.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted"));
        }
        erase_sector_4k(ch, addr, running)?;
        addr += SECTOR_SIZE;
    }

    let n_pages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
    ui::step("PROGRAM", &format!("{} pages ({} bytes)", n_pages, length));

    let mut offset = 0u32;
    let report_interval = (length / 4).max(PAGE_SIZE);
    let mut next_report = report_interval;

    while offset < length {
        if !running.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted"));
        }
        let page_remain = PAGE_SIZE - ((start + offset) % PAGE_SIZE);
        let data_remain = length - offset;
        let n = page_remain.min(data_remain) as usize;
        page_program(ch, start + offset, &data[offset as usize..offset as usize + n], running)?;
        offset += n as u32;
        if offset >= next_report || offset >= length {
            let pct = (offset as u64 * 100) / length as u64;
            ui::detail(&format!("{:#x} / {:#x} ({}%)", offset, length, pct));
            next_report += report_interval;
        }
    }
    ui::win("WRITE COMPLETE", &format!("{} bytes programmed at {:#x}", length, start));
    Ok(())
}

fn verify(
    ch: &mut dyn ByteChannel,
    start: u32,
    expected: &[u8],
    chunk: usize,
    running: &AtomicBool,
) -> io::Result<bool> {
    ui::step("VERIFY", &format!("{} bytes at {:#x}", expected.len(), start));
    let mut offset = 0u32;
    let total = expected.len() as u32;
    while offset < total {
        if !running.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted"));
        }
        let remain = (total - offset) as usize;
        let n = remain.min(chunk) as u32;
        let got = read_flash_chunk(ch, start + offset, n)?;
        let base = offset as usize;
        for (i, (&a, &b)) in expected[base..base + n as usize].iter().zip(got.iter()).enumerate() {
            if a != b {
                let addr = start + offset + i as u32;
                ui::fail(&format!(
                    "verify mismatch at {:#x}: expected {:#04x}, read {:#04x}",
                    addr, a, b
                ));
                return Ok(false);
            }
        }
        offset += n;
    }
    ui::win("VERIFY OK", &format!("{} bytes match", total));
    Ok(true)
}

// ── public entry point ──────────────────────────────────────────────────

pub enum SerprogOp {
    Identify,
    Read { output: String, start: u32, length: Option<u32> },
    Write { input: String, start: u32 },
    Erase,
    Verify { file: String, start: u32 },
}

pub fn serprog_flow(
    port: &str,
    baud: u32,
    op: SerprogOp,
    flash_size_override: Option<u32>,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    println!(
        "\n{}",
        "=== SERPROG (direct SPI flash) ===".bold().magenta()
    );
    println!("{} {} @ {} baud", "Programmer:".cyan(), port, baud);

    let mut p = serialport::new(port, baud)
        .timeout(Duration::from_millis(200))
        .open()
        .map_err(|e| format!("open {}: {}", port, e))?;

    let mut ch = crate::xfer::SerialChannel::new(&mut *p);
    let caps = handshake(&mut ch).map_err(|e| -> Box<dyn Error> {
        format!("serprog handshake failed: {} (check connection and baud rate)", e).into()
    })?;

    ui::found(&format!(
        "programmer '{}', serial buffer {} bytes",
        caps.name, caps.serbuf
    ));
    if caps.max_read > 0 {
        ui::detail(&format!("max read chunk: {} bytes", caps.max_read));
    }

    let chunk = read_chunk_size(&caps);

    let (chip_name, db_size) = identify(&mut ch)?;
    let chip_size = flash_size_override.unwrap_or(db_size);
    if chip_size == 0 {
        return Err("cannot determine flash size; use --flash-size <bytes>".into());
    }
    if chip_size > 16 * MB {
        ui::warn("chip > 16 MB: only the first 16 MB is addressable with 24-bit addressing");
    }

    println!(
        "{} {} ({} bytes / {} KB)",
        "Flash:".cyan(),
        chip_name,
        chip_size,
        chip_size / 1024,
    );

    match op {
        SerprogOp::Identify => {}
        SerprogOp::Read { output, start, length } => {
            let len = length.unwrap_or(chip_size - start);
            read_full(&mut ch, chip_size, start, len, &output, chunk, &running)?;
        }
        SerprogOp::Write { input, start } => {
            let data = std::fs::read(&input)
                .map_err(|e| format!("read {}: {}", input, e))?;
            if data.is_empty() {
                return Err("input file is empty".into());
            }
            ui::step("WRITE", &format!("{} bytes from {}", data.len(), input));
            write_full(&mut ch, chip_size, start, &data, &running)?;
            verify(&mut ch, start, &data, chunk, &running)?;
        }
        SerprogOp::Erase => {
            ui::step("ERASE", &format!("entire chip ({} bytes)", chip_size));
            erase_chip(&mut ch, &running)?;
            ui::win("ERASE COMPLETE", &format!("{} bytes erased", chip_size));
        }
        SerprogOp::Verify { file, start } => {
            let data = std::fs::read(&file)
                .map_err(|e| format!("read {}: {}", file, e))?;
            verify(&mut ch, start, &data, chunk, &running)?;
        }
    }
    Ok(())
}

// ── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xfer::ByteChannel;
    use std::io::{Read as IoRead, Write as IoWrite};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::AtomicBool;
    use std::thread;

    struct SockChan(UnixStream);
    impl ByteChannel for SockChan {
        fn read_byte(&mut self, timeout: Duration) -> io::Result<Option<u8>> {
            self.0.set_read_timeout(Some(timeout))?;
            let mut b = [0u8; 1];
            match self.0.read(&mut b) {
                Ok(1) => Ok(Some(b[0])),
                Ok(_) => Ok(None),
                Err(ref e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    Ok(None)
                }
                Err(e) => Err(e),
            }
        }
        fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            IoWrite::write_all(&mut self.0, buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            IoWrite::flush(&mut self.0)
        }
    }

    fn set_cmd_bit(map: &mut [u8; 32], cmd: u8) {
        map[(cmd / 8) as usize] |= 1 << (cmd % 8);
    }

    fn mock_serprog(mut s: UnixStream, mut flash: Vec<u8>) {
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut wren = false;
        let mut buf = [0u8; 1];
        loop {
            match IoRead::read(&mut s, &mut buf) {
                Ok(1) => {}
                _ => return,
            }
            match buf[0] {
                S_CMD_SYNCNOP => {
                    s.write_all(&[NAK, ACK]).unwrap();
                }
                S_CMD_Q_IFACE => {
                    s.write_all(&[ACK, 0x01, 0x00]).unwrap();
                }
                S_CMD_Q_CMDMAP => {
                    s.write_all(&[ACK]).unwrap();
                    let mut map = [0u8; 32];
                    for &c in &[
                        S_CMD_NOP, S_CMD_Q_IFACE, S_CMD_Q_CMDMAP, S_CMD_Q_PGMNAME,
                        S_CMD_Q_BUSTYPE, S_CMD_Q_SERBUF, S_CMD_S_BUSTYPE, S_CMD_O_SPIOP,
                        S_CMD_SYNCNOP,
                    ] {
                        set_cmd_bit(&mut map, c);
                    }
                    s.write_all(&map).unwrap();
                }
                S_CMD_Q_PGMNAME => {
                    s.write_all(&[ACK]).unwrap();
                    let mut name = [0u8; 16];
                    name[..12].copy_from_slice(b"baudowl-mock");
                    s.write_all(&name).unwrap();
                }
                S_CMD_Q_BUSTYPE => {
                    s.write_all(&[ACK, BUS_SPI]).unwrap();
                }
                S_CMD_Q_SERBUF => {
                    s.write_all(&[ACK]).unwrap();
                    s.write_all(&4096u16.to_le_bytes()).unwrap();
                }
                S_CMD_S_BUSTYPE => {
                    let mut tb = [0u8; 1];
                    let _ = IoRead::read_exact(&mut s, &mut tb);
                    s.write_all(&[ACK]).unwrap();
                }
                S_CMD_O_SPIOP => {
                    let mut lens = [0u8; 6];
                    if IoRead::read_exact(&mut s, &mut lens).is_err() {
                        return;
                    }
                    let slen =
                        u32::from_le_bytes([lens[0], lens[1], lens[2], 0]) as usize;
                    let rlen =
                        u32::from_le_bytes([lens[3], lens[4], lens[5], 0]) as usize;
                    let mut spi_data = vec![0u8; slen];
                    if slen > 0 {
                        if IoRead::read_exact(&mut s, &mut spi_data).is_err() {
                            return;
                        }
                    }
                    let resp = handle_spi(&mut flash, &spi_data, rlen, &mut wren);
                    s.write_all(&[ACK]).unwrap();
                    if !resp.is_empty() {
                        s.write_all(&resp).unwrap();
                    }
                }
                _ => {
                    s.write_all(&[NAK]).unwrap();
                }
            }
            IoWrite::flush(&mut s).unwrap();
        }
    }

    fn handle_spi(
        flash: &mut Vec<u8>,
        spi_data: &[u8],
        rlen: usize,
        wren: &mut bool,
    ) -> Vec<u8> {
        if spi_data.is_empty() {
            return vec![0; rlen];
        }
        match spi_data[0] {
            SPI_RDID => vec![0xEF, 0x40, 0x16], // W25Q32
            SPI_RDSR => vec![0x00],
            SPI_WREN => {
                *wren = true;
                Vec::new()
            }
            SPI_READ => {
                if spi_data.len() >= 4 {
                    let addr = ((spi_data[1] as u32) << 16)
                        | ((spi_data[2] as u32) << 8)
                        | (spi_data[3] as u32);
                    let a = addr as usize;
                    let end = (a + rlen).min(flash.len());
                    if a < flash.len() {
                        let mut out = flash[a..end].to_vec();
                        out.resize(rlen, 0xff);
                        out
                    } else {
                        vec![0xff; rlen]
                    }
                } else {
                    vec![0xff; rlen]
                }
            }
            SPI_PP => {
                if *wren && spi_data.len() >= 4 {
                    let addr = ((spi_data[1] as u32) << 16)
                        | ((spi_data[2] as u32) << 8)
                        | (spi_data[3] as u32);
                    let a = addr as usize;
                    for (i, &b) in spi_data[4..].iter().enumerate() {
                        if a + i < flash.len() {
                            flash[a + i] &= b;
                        }
                    }
                    *wren = false;
                }
                Vec::new()
            }
            SPI_SE_4K => {
                if *wren && spi_data.len() >= 4 {
                    let addr = ((spi_data[1] as u32) << 16)
                        | ((spi_data[2] as u32) << 8)
                        | (spi_data[3] as u32);
                    let a = (addr as usize) & !0xFFF;
                    let end = (a + 4096).min(flash.len());
                    for byte in &mut flash[a..end] {
                        *byte = 0xff;
                    }
                    *wren = false;
                }
                Vec::new()
            }
            SPI_CE => {
                if *wren {
                    for byte in flash.iter_mut() {
                        *byte = 0xff;
                    }
                    *wren = false;
                }
                Vec::new()
            }
            _ => vec![0; rlen],
        }
    }

    #[test]
    fn handshake_and_identify() {
        let flash = vec![0xff; 4 * 1024 * 1024]; // 4MB (W25Q32)
        let (a, b) = UnixStream::pair().unwrap();
        let h = thread::spawn(move || mock_serprog(b, flash));
        let mut ch = SockChan(a);
        let caps = handshake(&mut ch).unwrap();
        assert_eq!(caps.name, "baudowl-mock");
        assert_eq!(caps.serbuf, 4096);
        let (name, size) = identify(&mut ch).unwrap();
        assert_eq!(name, "Winbond W25Q32");
        assert_eq!(size, 4 * MB);
        drop(ch);
        h.join().unwrap();
    }

    #[test]
    fn read_flash_roundtrip() {
        let mut flash = vec![0xff; 8192];
        for (i, b) in flash.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        let expected = flash[0..512].to_vec();
        let (a, b) = UnixStream::pair().unwrap();
        let h = thread::spawn(move || mock_serprog(b, flash));
        let mut ch = SockChan(a);
        let _ = handshake(&mut ch).unwrap();
        let _ = read_jedec_id(&mut ch).unwrap();
        let got = read_flash_chunk(&mut ch, 0, 512).unwrap();
        assert_eq!(got, expected);
        drop(ch);
        h.join().unwrap();
    }

    #[test]
    fn write_and_readback() {
        let flash = vec![0xff; 8192];
        let (a, b) = UnixStream::pair().unwrap();
        let h = thread::spawn(move || mock_serprog(b, flash));
        let mut ch = SockChan(a);
        let _ = handshake(&mut ch).unwrap();
        let _ = read_jedec_id(&mut ch).unwrap();
        let running = AtomicBool::new(true);
        let payload: Vec<u8> = (0..256).map(|i| (i & 0xff) as u8).collect();
        erase_sector_4k(&mut ch, 0, &running).unwrap();
        page_program(&mut ch, 0, &payload, &running).unwrap();
        let got = read_flash_chunk(&mut ch, 0, 256).unwrap();
        assert_eq!(got, payload);
        let erased = read_flash_chunk(&mut ch, 256, 256).unwrap();
        assert!(erased.iter().all(|&b| b == 0xff));
        drop(ch);
        h.join().unwrap();
    }

    #[test]
    fn chip_lookup_and_fallback() {
        let w25q32 = lookup_chip(&[0xEF, 0x40, 0x16]);
        assert!(w25q32.is_some());
        assert_eq!(w25q32.unwrap().size, 4 * MB);
        assert!(lookup_chip(&[0xAA, 0xBB, 0xCC]).is_none());
        assert_eq!(guess_size_from_capacity_byte(0x18), Some(16 * MB));
        assert_eq!(guess_size_from_capacity_byte(0x10), None);
    }

    #[test]
    fn cmdmap_bit_ops() {
        let mut map = [0u8; 32];
        assert!(!cmd_supported(&map, S_CMD_O_SPIOP));
        set_cmd_bit(&mut map, S_CMD_O_SPIOP);
        assert!(cmd_supported(&map, S_CMD_O_SPIOP));
        assert!(!cmd_supported(&map, S_CMD_NOP));
    }
}
