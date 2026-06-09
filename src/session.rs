//! Interactive serial session: an expect-style engine for talking to a device
//! over UART. Supports timed reads, pattern matching on the incoming stream,
//! spamming a key to interrupt autoboot, and a line-buffered interactive bridge.

use std::io::{self, BufRead, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serialport::SerialPort;

/// Max number of decoded characters kept in the sliding match window.
const WINDOW_CAP: usize = 8192;

pub struct Session {
    port: Box<dyn SerialPort>,
    running: Arc<AtomicBool>,
    /// Mirror device output to stdout as it arrives.
    pub echo: bool,
    /// Full transcript of everything read from the device.
    pub log: Vec<u8>,
}

impl Session {
    /// Open the port at the given baudrate using 8N1, no flow control.
    pub fn open(path: &str, baud: u32, running: Arc<AtomicBool>) -> io::Result<Self> {
        let port = serialport::new(path, baud)
            .data_bits(serialport::DataBits::Eight)
            .parity(serialport::Parity::None)
            .stop_bits(serialport::StopBits::One)
            .flow_control(serialport::FlowControl::None)
            .timeout(Duration::from_millis(100))
            .open()
            .map_err(|e| io::Error::other(e.to_string()))?;
        port.clear(serialport::ClearBuffer::All).ok();
        Ok(Self {
            port,
            running,
            echo: false,
            log: Vec::new(),
        })
    }

    fn still_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Write raw bytes and flush (no line terminator added).
    pub fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.port.write_all(bytes)?;
        self.port.flush()
    }

    /// Assert or release the DTR control line.
    pub fn set_dtr(&mut self, level: bool) -> io::Result<()> {
        self.port
            .write_data_terminal_ready(level)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// Assert or release the RTS control line.
    pub fn set_rts(&mut self, level: bool) -> io::Result<()> {
        self.port
            .write_request_to_send(level)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// Write a command followed by a carriage return (U-Boot line terminator).
    pub fn send_line(&mut self, line: &str) -> io::Result<()> {
        self.port.write_all(line.as_bytes())?;
        self.port.write_all(b"\r")?;
        self.port.flush()
    }

    fn consume(&mut self, buf: &[u8], window: &mut String) {
        self.log.extend_from_slice(buf);
        if self.echo {
            let mut out = io::stdout();
            let _ = out.write_all(buf);
            let _ = out.flush();
        }
        for &b in buf {
            window.push(if (0x20..=0x7e).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' {
                b as char
            } else {
                '.'
            });
        }
        if window.len() > WINDOW_CAP {
            let cut = window.len() - WINDOW_CAP;
            *window = window.split_off(cut);
        }
    }

    fn match_any(window: &str, patterns: &[String]) -> Option<usize> {
        let lw = window.to_ascii_lowercase();
        patterns
            .iter()
            .position(|p| lw.contains(&p.to_ascii_lowercase()))
    }

    /// Read until one of `patterns` appears in the stream or `timeout` elapses.
    /// Returns the matched index and the accumulated window text on success.
    pub fn expect(&mut self, patterns: &[String], timeout: Duration) -> Option<(usize, String)> {
        let deadline = Instant::now() + timeout;
        let mut window = String::new();
        let mut buf = [0u8; 512];
        while Instant::now() < deadline && self.still_running() {
            match self.port.read(&mut buf) {
                Ok(n) if n > 0 => {
                    self.consume(&buf[..n], &mut window);
                    if let Some(i) = Self::match_any(&window, patterns) {
                        return Some((i, window));
                    }
                }
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {}
                Err(_) => {}
            }
        }
        None
    }

    /// Spam `key` every `interval` while watching for any of `patterns`.
    /// This is how the autoboot countdown is interrupted. Returns the matched
    /// index and window text on success.
    pub fn spam_until(
        &mut self,
        key: &[u8],
        patterns: &[String],
        timeout: Duration,
        interval: Duration,
    ) -> Option<(usize, String)> {
        let deadline = Instant::now() + timeout;
        let mut last_send: Option<Instant> = None;
        let mut window = String::new();
        let mut buf = [0u8; 512];
        while Instant::now() < deadline && self.still_running() {
            let due = match last_send {
                None => true,
                Some(t) => t.elapsed() >= interval,
            };
            if due {
                let _ = self.port.write_all(key);
                let _ = self.port.flush();
                last_send = Some(Instant::now());
            }
            match self.port.read(&mut buf) {
                Ok(n) if n > 0 => {
                    self.consume(&buf[..n], &mut window);
                    if let Some(i) = Self::match_any(&window, patterns) {
                        return Some((i, window));
                    }
                }
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {}
                Err(_) => {}
            }
        }
        None
    }

    /// Read for a fixed duration and return the decoded text seen.
    pub fn collect(&mut self, dur: Duration) -> String {
        let deadline = Instant::now() + dur;
        let mut window = String::new();
        let mut buf = [0u8; 512];
        while Instant::now() < deadline && self.still_running() {
            match self.port.read(&mut buf) {
                Ok(n) if n > 0 => self.consume(&buf[..n], &mut window),
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {}
                Err(_) => {}
            }
        }
        window
    }

    /// Line-buffered interactive bridge: stdin lines are sent to the device
    /// (terminated with CR) and device output is streamed to stdout until the
    /// running flag is cleared (Ctrl-C).
    pub fn interactive(&mut self) -> io::Result<()> {
        let mut writer = self.port.try_clone()?;
        let r = self.running.clone();
        std::thread::spawn(move || {
            let stdin = io::stdin();
            let mut line = String::new();
            loop {
                if !r.load(Ordering::SeqCst) {
                    break;
                }
                line.clear();
                match stdin.lock().read_line(&mut line) {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        let cmd = line.trim_end_matches(['\n', '\r']);
                        if writer.write_all(cmd.as_bytes()).is_err() {
                            break;
                        }
                        let _ = writer.write_all(b"\r");
                        let _ = writer.flush();
                    }
                    Err(_) => break,
                }
            }
        });

        let mut buf = [0u8; 512];
        let mut out = io::stdout();
        while self.still_running() {
            match self.port.read(&mut buf) {
                Ok(n) if n > 0 => {
                    out.write_all(&buf[..n])?;
                    out.flush()?;
                }
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
        Ok(())
    }
}
