# 🦉 BaudOwl

<img width="200" height="200" alt="baudowl" src="https://github.com/user-attachments/assets/8659798d-e6ad-4126-868a-7ef65839c13f" />


**The Ultimate Serial Port Detective**

```
    )___(
    (o o)   BaudOwl v1.6.0
   /  V  \  -------------------
  /(     )\  The Serial Port Detective
    ^^ ^^   Sniffs out baudrates in seconds!
```
## Features

- 🚀 Automatic baudrate detection
- ⚡ Turbo mode for fast scanning
- 🚨 High-speed mode (up to 4,000,000 baud)
- 🐚 U-Boot autoroot: interrupt autoboot, inject `bootargs`, drop to a root shell
- 🧲 Firmware extraction over UART (U-Boot `md.b`/flash read, or base64 from a shell)
- 🧬 Binary protocol fingerprinting (Modbus/NMEA/MAVLink) and framing autodetect
- 🤖 Expect-style scripting, default-credential testing, secret harvesting
- 🔌 DTR/RTS auto-reset, serial BREAK, and glitch-trigger coordination
- ⏱️ Timing side-channel attack and leakage assessment on console checks
- 🐛 Serial fuzzer (raw or protocol-aware) with crash oracle, auto-reset, and repro minimization
- 🕵️ Passive sniffing, replay, and a MITM bridge with in-transit byte rewrite
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

## Advanced capabilities

All of these run over the same serial line. For lab/authorized use only.

### Firmware extraction

```bash
# Dump 1 MB of SPI flash to firmware.bin (breaks into U-Boot, then sf read + md.b)
baudowl --baud 115200 --dump-flash --dump-source sf --dump-offset 0x0 \
        --dump-length 0x100000 --dump-out firmware.bin

# Dump device RAM directly via md.b
baudowl --baud 115200 --dump-mem 0x80000000 --dump-length 0x1000 --dump-out ram.bin

# Pull a file from an already-rooted shell (base64 over UART)
baudowl --baud 115200 --shell-dump /etc/shadow --dump-out shadow.txt

# Patch a byte in memory (for example before bootm)
baudowl --baud 115200 --write-mem 0x80010000 --write-value 0x90 --write-count 1
```

`--dump-source` is `sf` (SPI), `nand`, or `mmc`. `mmc` byte offsets are converted to 512-byte block addressing automatically.

### Detection

```bash
baudowl --baud 9600 --detect-framing     # try 8N1/7E1/7O1/8E1/8O1/8N2/7N1, pick the cleanest
baudowl --baud 9600 --detect-protocol    # fingerprint Modbus RTU / NMEA / MAVLink
baudowl --sigrok-driver fx2lafw --sigrok-samplerate 8000000   # logic-analyzer auto-baud
```

### Automation

```bash
baudowl --baud 115200 --script flow.txt              # run an expect-style script
baudowl --baud 115200 --cred-brute                   # try default console credentials
baudowl --baud 115200 --harvest --dump-out loot.txt  # scrape secrets from a root shell
```

Script DSL (one command per line, `#` for comments):

```
send <text>            send text plus CR (escapes: \n \r \t \xNN)
sendraw <hex>          send raw bytes, e.g. sendraw de ad be ef
expect [secs] <pat>    wait for a substring (default 10s)
delay <ms>             read/drain for a fixed time
log <message>          print a line
```

### Hardware triggering

```bash
baudowl --port /dev/ttyUSB0 --reset esp                 # DTR/RTS reset: dtr|rts|esp
baudowl --port /dev/ttyUSB0 --send-break --break-ms 300 # timed serial BREAK (Unix)

# Fire a trigger (RTS/DTR pulse and/or a command) when a boot marker appears
baudowl --baud 115200 --glitch-on "Verifying" --glitch-line rts \
        --glitch-cmd "./chipwhisperer_glitch.py"
```

### Timing side-channel

Recover a secret from a non-constant-time console check, or assess whether a check leaks timing.

```bash
# Recover a password char-by-char from rejection timing
baudowl --baud 115200 --timing-attack --timing-marker "incorrect" \
        --timing-charset "abcdefghijklmnopqrstuvwxyz0123456789" --timing-samples 30

# TVLA-lite: is the check constant-time? (Welch t-test over two input classes)
baudowl --baud 115200 --leakage-test \
        --timing-class-a "correctprefix" --timing-class-b "wrongguess"
```

The per-character delay must exceed UART jitter; raise `--timing-samples` on noisy links.

### Serial fuzzing

Fuzz a console or protocol parser, detect crashes from the serial output, auto-reset, and minimize the crashing input to a deterministic repro.

```bash
baudowl --baud 115200 --fuzz --fuzz-maxlen 256 --fuzz-iterations 5000 \
        --fuzz-reset dtr --fuzz-seed 1
```

Crashes are matched by signature (kernel panic, data abort, watchdog, and more; add your own with `--fuzz-crash-sig`). Reset between crashes via `--fuzz-reset dtr|rts|cmd|none`. Runs are reproducible from `--fuzz-seed`, and each crashing input is reduced by delta debugging. Use `--fuzz-protocol modbus|nmea` for structure-aware cases (valid frames with field corruption) instead of raw bytes.

### Interception

Sit on the line passively, or inline between two endpoints.

```bash
# Passive read-only capture: timestamps, frame splitting, protocol decode
baudowl --baud 9600 --sniff --sniff-decode --sniff-out capture.bin

# Capture boot output by resetting on the same open port (no reset/capture race).
# ESP8266/NodeMCU boot ROM prints at 74880 baud; --sniff-reset dtr|rts|esp
baudowl --baud 74880 --sniff --sniff-reset esp

# Replay a captured or crafted byte log back out the port
baudowl --baud 9600 --replay capture.bin

# Man-in-the-middle: bridge two ports and rewrite bytes in transit
baudowl --baud 115200 --port /dev/ttyUSB0 --mitm --mitm-port-b /dev/ttyUSB1 \
        --mitm-rule "a2b:deadbeef:cafebabe"
```

### Verification status

- **Unit-tested logic (48 tests):** `md.b` parsing, base64, Modbus CRC16 (canonical `0x4B37`), NMEA checksum, MAVLink framing, Modbus/NMEA frame builders, script parser, secret patterns, sigrok baud math, mmc block addressing, Welch t-test and outlier statistics, PRNG determinism, delta-debugging minimization, MITM rule rewriting, idle-gap frame splitting.
- **Proven end-to-end against a simulated device:** autoroot, flash and RAM dump (exact byte reconstruction), base64 shell dump, credential test, timing attack (secret recovered char-by-char), fuzzer (crash found and minimized to the trigger byte), passive sniff (capture and protocol decode), MITM bridge (forward and rewrite in transit).
- **Verified on real hardware (ESP8266 NodeMCU, CP2102 bridge):** port access, baudrate detection, passive sniff with boot-ROM capture via `--sniff-reset`, DTR/RTS reset, and the interactive script engine (AT queries returning firmware version and `OK`).
- **Code-complete, needs other hardware to verify:** serial BREAK, glitch trigger output, framing autodetect, sigrok-cli capture.

---

## Example Output

Baudrate detection:

```text
    )___(
    (o o)   BAUDOWL v1.6.0
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
