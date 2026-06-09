//! Hardware reset over the serial control lines, and serial BREAK injection.
//! Toggling DTR/RTS lets the tool drop a target into its boot window without a
//! manual power cycle. The line-to-signal mapping depends on the adapter wiring
//! (for example esptool maps DTR->IO0 and RTS->EN); this drives the lines, the
//! board decides what they do.

use std::error::Error;
use std::thread::sleep;
use std::time::Duration;

use colored::*;

/// Pulse a reset using one of the named profiles: `dtr`, `rts`, or `esp`.
pub fn pulse_reset(port: &str, baud: u32, profile: &str) -> Result<(), Box<dyn Error>> {
    let mut p = serialport::new(port, baud)
        .timeout(Duration::from_millis(100))
        .open()
        .map_err(|e| format!("open {}: {}", port, e))?;
    let prof = profile.to_ascii_lowercase();
    println!("{} reset profile '{}' on {}", "[*]".cyan(), prof, port);
    match prof.as_str() {
        "dtr" => {
            p.write_data_terminal_ready(true)?;
            sleep(Duration::from_millis(120));
            p.write_data_terminal_ready(false)?;
        }
        "rts" => {
            p.write_request_to_send(true)?;
            sleep(Duration::from_millis(120));
            p.write_request_to_send(false)?;
        }
        "esp" => {
            // esptool classic reset sequence (DTR->IO0, RTS->EN).
            p.write_data_terminal_ready(false)?;
            p.write_request_to_send(true)?;
            sleep(Duration::from_millis(100));
            p.write_data_terminal_ready(true)?;
            p.write_request_to_send(false)?;
            sleep(Duration::from_millis(50));
            p.write_data_terminal_ready(false)?;
        }
        other => {
            return Err(format!("unknown reset profile '{}' (use dtr|rts|esp)", other).into())
        }
    }
    println!("{} reset pulse sent", "[+]".green());
    Ok(())
}

/// Assert a timed serial BREAK using the TTY's raw fd (Linux/Unix only).
#[cfg(unix)]
pub fn send_break(port: &str, baud: u32, duration_ms: u64) -> Result<(), Box<dyn Error>> {
    use std::os::unix::io::AsRawFd;
    let tty = serialport::new(port, baud)
        .timeout(Duration::from_millis(100))
        .open_native()
        .map_err(|e| format!("open {}: {}", port, e))?;
    let fd = tty.as_raw_fd();
    println!("{} asserting BREAK for {}ms on {}", "[*]".cyan(), duration_ms, port);
    let set = unsafe { libc::ioctl(fd, libc::TIOCSBRK as _) };
    if set != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    sleep(Duration::from_millis(duration_ms.max(1)));
    let clear = unsafe { libc::ioctl(fd, libc::TIOCCBRK as _) };
    if clear != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    println!("{} BREAK released", "[+]".green());
    Ok(())
}

#[cfg(not(unix))]
pub fn send_break(_port: &str, _baud: u32, _duration_ms: u64) -> Result<(), Box<dyn Error>> {
    Err("BREAK injection is only implemented on Unix".into())
}
