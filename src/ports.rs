//! Serial port enumeration with USB identity (the `--list` command).

use colored::*;
use serialport::SerialPortType;

fn detail(t: &SerialPortType) -> String {
    match t {
        SerialPortType::UsbPort(info) => {
            let mfg = info.manufacturer.clone().unwrap_or_default();
            let prod = info.product.clone().unwrap_or_default();
            let sn = info
                .serial_number
                .clone()
                .map(|s| format!("  [sn {}]", s))
                .unwrap_or_default();
            let text = format!("USB {:04x}:{:04x}  {} {}{}", info.vid, info.pid, mfg, prod, sn);
            text.split_whitespace().collect::<Vec<_>>().join(" ")
        }
        SerialPortType::PciPort => "PCI".to_string(),
        SerialPortType::BluetoothPort => "Bluetooth".to_string(),
        SerialPortType::Unknown => "unknown bus".to_string(),
    }
}

/// List serial ports. By default only real plug-in devices (USB, Bluetooth);
/// `all` also shows legacy PCI/unknown ports (the `/dev/ttyS*` noise).
pub fn list_ports(all: bool) {
    println!("{}", "=== AVAILABLE SERIAL PORTS ===".bold().magenta());
    let ports = match serialport::available_ports() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} {}", "error listing ports:".red().bold(), e);
            return;
        }
    };
    let (mut shown, mut hidden) = (0usize, 0usize);
    for p in &ports {
        let interesting = matches!(
            p.port_type,
            SerialPortType::UsbPort(_) | SerialPortType::BluetoothPort
        );
        if !interesting && !all {
            hidden += 1;
            continue;
        }
        println!(
            "  {}  {}",
            format!("{:<14}", p.port_name).bold().cyan(),
            detail(&p.port_type).dimmed()
        );
        shown += 1;
    }
    if shown == 0 {
        println!("{}", "  (no USB/Bluetooth serial devices)".yellow());
    }
    if hidden > 0 {
        println!(
            "\n{} {} device(s); {} legacy/other port(s) hidden ({})",
            "[+]".bold().green(),
            shown,
            hidden,
            "--list-all to show".dimmed()
        );
    } else {
        println!("\n{} {} port(s)", "[+]".bold().green(), shown);
    }
}
