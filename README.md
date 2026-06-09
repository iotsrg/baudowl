# 🦉 BaudOwl

<img width="200" height="200" alt="baudowl" src="https://github.com/user-attachments/assets/8659798d-e6ad-4126-868a-7ef65839c13f" />


**The Ultimate Serial Port Detective**

```
    )___(
    (o o)   BaudOwl v1.2
   /  V  \  -------------------
  /(     )\  The Serial Port Detective
    ^^ ^^   Sniffs out baudrates in seconds!
```
## Features

- 🚀 Automatic baudrate detection
- ⚡ Turbo mode for fast scanning
- 🚨 High-speed mode (up to 4,000,000 baud)
- 🐚 U-Boot autoroot: interrupt autoboot, inject `bootargs`, drop to a root shell
- 📊 Real-time detection statistics
- 🔧 Minicom configuration generator
- 🎨 Colorful and readable terminal output


## Installation

### Prerequisites

- **Rust** (version ≥ 1.74) - [Install via rustup](https://rustup.rs)
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

# U-Boot autoroot (authorized lab targets only)
baudowl --baud 115200 --autoroot --dry-run        # show commands, change nothing
baudowl --baud 115200 --autoroot                  # volatile setenv + boot to shell
baudowl --port /dev/ttyUSB0 --autoroot --interrupt-key ctrl-c
```

---

## Command-Line Options

| Option            | Description                            | Default        |
|------------------|----------------------------------------|----------------|
| `-p`, `--port`    | Serial port device                     | `/dev/ttyUSB0` |
| `-t`, `--timeout` | Detection timeout (seconds)            | `5`            |
| `-c`, `--threshold`| Min readability score (0-100) to accept a rate | `60`     |
| `-n`, `--name`    | Save config and launch Minicom         | `-`            |
| `-a`, `--auto`    | Force a scan even when `--baud` is set  | `false`        |
| `-b`, `--baudlist`| Show supported baudrates               | `false`        |
| `-q`, `--quiet`   | Suppress data output                   | `false`        |
| `--turbo`         | Fast scan (common baudrates only)      | `false`        |
| `--highspeed`     | Enable scan for 1M+ baudrates          | `false`        |
| `--baud <N>`      | Force a baudrate, skip auto-detection  | `-`            |

### Autoroot options (U-Boot shell via bootargs)

| Option              | Description                                         | Default        |
|---------------------|-----------------------------------------------------|----------------|
| `--autoroot`        | Break into U-Boot, inject shell bootargs, get shell | `false`        |
| `--shell-arg <S>`   | Boot argument or preset name to obtain a shell (see `--list-shell-args`) | `init=/bin/sh` |
| `--interrupt-key <K>`| Key spammed to stop autoboot: `enter`/`space`/`ctrl-c`/`esc`/`\xNN` | `enter` |
| `--break-timeout <S>`| Seconds to spam the interrupt key                  | `30`           |
| `--single`          | Also append the `single` (single-user) flag         | `false`        |
| `--boot-cmd <C>`    | Command used to continue booting after setenv       | `boot`         |
| `--persist`         | `saveenv` to flash (persistent, **dangerous**)      | `false`        |
| `--dry-run`         | Print commands that would be sent, change nothing   | `false`        |
| `--list-shell-args` | List the shell boot-argument presets and exit       | `false`        |

---

## Autoroot: U-Boot bootargs shell

When the target exposes a U-Boot console on UART, `--autoroot` automates the
classic `init=/bin/sh` boot-argument attack:

1. Spam `--interrupt-key` during the autoboot countdown to reach the bootloader prompt.
2. Confirm the console **responds to commands** (`version` banner) before changing anything.
3. `printenv bootargs`, parse it, and replace/insert the shell argument
   (existing `init=`/`rdinit=` is replaced; `quiet`/`splash` are stripped).
4. `setenv bootargs <new>` then `boot`, then drop into an interactive bridge.

**Safety / scope:** authorized lab targets only. Changes are **volatile** by
default (a power cycle restores the original `bootargs`); `--persist` (`saveenv`)
is opt-in. It aborts before any change if the UART does not confirm responsive.
This is a logic-level PoC: it stops at "you have a root shell" (verify with
`id` / `cat /proc/version`); no payload is delivered. Use `--dry-run` first.

```text
[A] Bootloader prompt reached.
[B] Responsive. U-Boot 2018.03 (Jan 01 2020 - 00:00:00) board-xyz
[C] Reading current environment...
[D] bootargs rewrite:
    old: console=ttyS0,115200 root=/dev/mtdblock2 init=/sbin/init
    new: console=ttyS0,115200 root=/dev/mtdblock2 init=/bin/sh
[E] Booting: boot
[F] Shell reached. Interactive bridge (Ctrl-C exits). Verify: id; cat /proc/version
```

### Shell boot-argument presets

`--shell-arg` accepts a preset name or a raw boot argument. List them with `baudowl --list-shell-args`:

| Preset | Boot argument | Notes |
|--------|---------------|-------|
| `sh` | `init=/bin/sh` | most common, no auth (covers BusyBox `/bin/sh`) |
| `bash` | `init=/bin/bash` | if bash is present, no auth |
| `sbin-sh` | `init=/sbin/sh` | some embedded layouts, no auth |
| `ash` | `init=/bin/ash` | BusyBox ash where `/bin/ash` exists, no auth |
| `rdinit` | `rdinit=/bin/sh` | initramfs/initrd, shell before the real root pivots, no auth |
| `single` | `single` | single-user (may prompt for the root password) |
| `s` | `S` | single-user, sysvinit style (may prompt for the root password) |
| `rescue` | `systemd.unit=rescue.target` | systemd rescue (usually prompts for the root password) |
| `emergency` | `systemd.unit=emergency.target` | systemd emergency (usually prompts for the root password) |

Any other value is used verbatim, e.g. `--shell-arg "init=/bin/sh rw console=ttyS0,115200"`. The `init=`/`rdinit=` family replaces the device init and bypasses login; `single` and systemd targets may still require the root password. Existing `init=`/`rdinit=` and `quiet`/`splash` tokens are handled automatically.

---

## Example Output

Baudrate detection:

```text
    )___(
    (o o)   BAUDOWL v1.2
   /  V  \  -------------------
  /(     )\  The Serial Port Detective
    ^^ ^^   Sniffs out baudrates in seconds!

Starting detection...
Testing 16 baud rates...

Testing:  115200 baud... [U-Boot 2018.03 (Jan 01 2020 -] MATCH! (score: 88%)

🦉 HOOT! Detected baudrate: 115200

=== Detection Statistics ===
Baudrates tried: 1
Bytes processed: 50
Detection time: 124.50ms
```
