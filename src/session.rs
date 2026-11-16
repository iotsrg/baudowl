use std::io::{self, BufRead, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serialport::SerialPort;

const WINDOW_CAP: usize = 8192;

pub struct Session {
    port: Box<dyn SerialPort>,
    running: Arc<AtomicBool>,
    pub echo: bool,
    pub log: Vec<u8>,
}

impl Session {
    pub fn open(path: &str, baud: u32, running: Arc<AtomicBool>) -> io::Result<Self> {
        let port = serialport::new(path, baud)
            .data_bits(serialport::DataBits::Eight)
            .parity(serialport::Parity::None)
            .stop_bits(serialport::StopBits::One)
            .flow_control(serialport::FlowControl::None)
            .timeout(Duration::from_millis(100))
            .open()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
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

    pub fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.port.write_all(bytes)?;
        self.port.flush()
    }

    pub fn start_capture(&mut self) {
        self.log.clear();
    }

    pub fn set_dtr(&mut self, level: bool) -> io::Result<()> {
        self.port
            .write_data_terminal_ready(level)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    pub fn set_rts(&mut self, level: bool) -> io::Result<()> {
        self.port
            .write_request_to_send(level)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    pub fn transfer_out(
        &mut self,
        data: &[u8],
        mode: crate::xfer::XferMode,
        filename: &str,
    ) -> io::Result<u64> {
        let running = self.running.clone();
        let mut ch = crate::xfer::SerialChannel::new(&mut *self.port);
        crate::xfer::send(&mut ch, data, mode, filename, &running)
    }

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

    pub fn monitor(&mut self, raw: bool) -> io::Result<()> {
        let mut buf = [0u8; 512];
        let mut out = io::stdout();
        while self.still_running() {
            match self.port.read(&mut buf) {
                Ok(n) if n > 0 => {
                    if raw {
                        out.write_all(&buf[..n])?;
                    } else {
                        let safe: Vec<u8> = buf[..n]
                            .iter()
                            .map(|&b| {
                                if (0x20..=0x7e).contains(&b)
                                    || matches!(b, b'\n' | b'\r' | b'\t')
                                {
                                    b
                                } else {
                                    b'.'
                                }
                            })
                            .collect();
                        out.write_all(&safe)?;
                    }
                    out.flush()?;
                }
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

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
