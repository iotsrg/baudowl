const BANNER: &str = r#"
    )___(
    (o o)  🐕  BAUDHOUND v1.1
   /  V  \  -------------------
  /(     )\  The Serial Port Detective
    ^^ ^^   Sniffs out baudrates in seconds!
"#;

# BaudSolver
Identify Unknown and custom baudrate values.
# Identify Unknown and Custom Baud Rate Values

This project aims to simplify the process of identifying unknown or custom baud rates when working with UART pins in hardware hacking and debugging. Misconfigured or unknown baud rates can lead to frustrating trial-and-error processes, but this tool makes it hassle-free.

---

## Features

- **Automatic Baud Rate Detection**: Identify standard and custom baud rates with ease.
- **Support for Common Baud Rates**: Pre-configured to detect standard rates like 9600, 115200, and more.
- **User-Friendly**: Minimal setup required, with a clear and intuitive output.
- **Customizable**: Add or modify baud rate ranges to fit your specific hardware needs.

---

## Getting Started

### Prerequisites

- A machine running Linux (preferred) or other operating systems with UART communication support.
- [Rust](https://www.rust-lang.org/) installed on your system.
- Basic understanding of UART communication.

### Installation

Install the tool directly from crates.io using Cargo:
```bash
cargo install baudrate-detector
```

---

## Usage

1. Connect your UART device to your system.
2. Run the tool and specify the serial port:
   ```bash
   baudrate-detector --port /dev/ttyUSB0
   ```
3. The tool will cycle through common baud rates and display the correct value once detected.

### Supported Baud Rates
By default, the tool tests the following baud rates:
- 9600
- 19200
- 38400
- 57600
- 115200
- 230400
- 460800
- 921600

You can modify this list by editing the configuration file if needed.

---

## Contributing
We welcome contributions to improve the tool! Here’s how you can contribute:

1. Fork the repository.
2. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Commit your changes and push to your fork.
4. Open a pull request with a clear description of your changes.

---

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---

## Acknowledgments

- Inspired by the challenges faced in UART debugging and hardware hacking.
- Special thanks to the IoT Security Research community for their input and support.

---

## Contact
For questions or feedback, feel free to reach out:
- Email: your.email@example.com
- GitHub Issues: [Create an Issue](https://github.com/your-username/identify-baudrate-values/issues)

Happy debugging! 🚀
