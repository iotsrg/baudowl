# 🦉 BaudOwl

<img width="200" height="200" alt="baudowl" src="https://github.com/user-attachments/assets/8659798d-e6ad-4126-868a-7ef65839c13f" />


**The Ultimate Serial Port Detective**

```
    )___(
    (o o)   BaudOwl v1.0
   /  V  \  -------------------
  /(     )\  The Serial Port Detective
    ^^ ^^   Sniffs out baudrates in seconds!
```
## Features

- 🚀 Automatic baudrate detection
- ⚡ Turbo mode for fast scanning
- 🚨 High-speed mode (up to 4,000,000 baud)
- 📊 Real-time detection statistics
- 🔧 Minicom configuration generator
- 🎨 Colorful and readable terminal output


## Installation

### Prerequisites

- **Rust** (version ≥ 1.70) - [Install via rustup](https://rustup.rs)
- **Linux Packages**:
  ```bash
  sudo apt install libudev-dev pkg-config
  ```

### Build from Source

```bash
git clone https://github.com/iotsrg/baudowl.git
cd baudowl
cargo build --release
sudo cp target/release/baudowl /usr/local/bin/
```

---

## Usage

```bash
baudowl --port /dev/ttyUSB0
baudowl --highspeed --auto
baudowl --turbo --quiet
baudowl --name mydevice
baudowl --help
```

---

## Command-Line Options

| Option            | Description                            | Default        |
|------------------|----------------------------------------|----------------|
| `-p`, `--port`    | Serial port device                     | `/dev/ttyUSB0` |
| `-t`, `--timeout` | Detection timeout (seconds)            | `5`            |
| `-c`, `--threshold`| ASCII character detection threshold    | `25`           |
| `-n`, `--name`    | Save config and launch Minicom         | `-`            |
| `-a`, `--auto`    | Enable auto-detection mode             | `false`        |
| `-b`, `--baudlist`| Show supported baudrates               | `false`        |
| `-q`, `--quiet`   | Suppress data output                   | `false`        |
| `--turbo`         | Fast scan (common baudrates only)      | `false`        |
| `--highspeed`     | Enable scan for 1M+ baudrates          | `false`        |

---

## Example Output

```
[+] Scanning /dev/ttyUSB0...
[✓] Baudrate Detected: 115200
[✓] Protocol: UART ASCII
[✓] Minicom profile generated: mydevice
[] Challenge 2
[] challenge 3
```

---

## Authors & Credits

Developed with ❤️ by the [IoT Security Research Group](https://github.com/iotsrg)  
Logo and tooling inspired by field use cases in embedded security and UART fuzzing.

---

## License

This project is licensed under the [MIT License](LICENSE).
