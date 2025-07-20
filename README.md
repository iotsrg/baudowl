## BaudOwl 
**The Ultimate Serial Port Detective**
```
    )___(
    (o o)   BaudOwl v1.1
   /  V  \  -------------------
  /(     )\  The Serial Port Detective
    ^^ ^^   Sniffs out baudrates in seconds!
```
### Features
- 🚀 Automatic baudrate detection
- ⚡ Turbo mode for fast scanning
- 🚨 High-speed mode (up to 4,000,000 baud)
- 📊 Detection statistics and analytics
- 🔧 Minicom configuration generator
- 🎨 Colorful terminal output

### Installation

#### Prerequisites
- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- Linux: `libudev-dev` and `pkg-config`
  ```bash
  sudo apt-get install libudev-dev pkg-config
  ```

  #### Build from source
  ```bash
  git clone https://github.com/iotsrg/baudowl.git
  cd baudowl
  cargo build --release
  sudo cp target/release/baudowl /usr/local/bin/
  ```

  #### Usage
  ```bash
  baudowl --port /dev/ttyUSB0
  baudowl --highspeed --auto
  baudowl --turbo --quiet
  baudowl --name mydevice
  baudowl --help
  Option	Description	Default

  ```
  -p, --port	Serial port device	/dev/ttyUSB0
-t, --timeout	Detection timeout (seconds)	5
-c, --threshold	ASCII character threshold	25
-n, --name	Save config and launch Minicom	-
-a, --auto	Enable auto-detection mode	false
-b, --baudlist	Show supported baudrates	false
-q, --quiet	Suppress data output	false
--turbo	Fast scan (common rates only)	false
--highspeed	Enable 1Mbps+ baudrates	false
