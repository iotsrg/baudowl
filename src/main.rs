use std::{
    io::{self, Read, Write},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use clap::Parser;
use ctrlc;
use colored::*;

use std::path::Path;

/// Validate config name contains only safe characters (alphanumeric, dash, underscore)
fn validate_config_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Config name cannot be empty".to_string());
    }
    if name.len() > 64 {
        return Err("Config name too long (max 64 chars)".to_string());
    }
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err("Config name can only contain alphanumeric characters, dashes, and underscores".to_string());
    }
    Ok(())
}

/// Validate serial port path is a valid device path
fn validate_port_path(port: &str) -> Result<(), String> {
    // Must start with /dev/
    if !port.starts_with("/dev/") {
        return Err("Port must be a device path starting with /dev/".to_string());
    }
    // No path traversal
    if port.contains("..") {
        return Err("Port path cannot contain '..'".to_string());
    }
    // No newlines or control characters (prevents config injection)
    if port.chars().any(|c| c.is_control()) {
        return Err("Port path cannot contain control characters".to_string());
    }
    // Validate it looks like a real device path
    let path = Path::new(port);
    if path.components().count() > 4 {
        return Err("Port path too deep".to_string());
    }
    Ok(())
}

const BANNER: &str = r#"
    )___(
    (o o)   BAUDOWL v1.1
   /  V  \  -------------------
  /(     )\  The Serial Port Detective
    ^^ ^^   Sniffs out baudrates in seconds!
"#;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "baudowl - The Ultimate Serial Port Detective",
    long_about = None,
    after_help = "Examples:\n  baudowl -p /dev/ttyACM0 --highspeed\n  baudowl --turbo -q\n  baudowl -n myconfig --auto"
)]
struct Args {
    /// Specify serial port to use
    #[arg(short, long, default_value = "/dev/ttyUSB0")]
    port: String,

    /// Set timeout period (seconds) in auto-detect mode
    #[arg(short, long, default_value_t = 5)]
    timeout: u64,

    /// Set minimum ASCII character threshold
    #[arg(short, long, default_value_t = 25)]
    threshold: usize,

    /// Save config as <name> and invoke Minicom (implies --auto)
    #[arg(short, long)]
    name: Option<String>,

    /// Enable auto-detect mode
    #[arg(short, long)]
    auto: bool,

    /// Display supported baud rates and exit
    #[arg(short, long)]
    baudlist: bool,

    /// Suppress data display (quiet mode)
    #[arg(short, long)]
    quiet: bool,

    /// Enable turbo mode (faster detection)
    #[arg(short, long)]
    turbo: bool,

    /// Enable ultra-high baudrates (1Mbps+)
    #[arg(long)]
    highspeed: bool,
}

struct BaudOwl {
    args: Args,
    running: Arc<AtomicBool>,
    stats: DetectionStats,
}

#[derive(Default)]
struct DetectionStats {
    bytes_processed: usize,
    baudrates_tried: usize,
    detection_time: Duration,
}

impl BaudOwl {
    fn new(args: Args) -> Result<Self, String> {
        // Validate inputs before proceeding
        validate_port_path(&args.port)?;
        if let Some(ref name) = args.name {
            validate_config_name(name)?;
        }

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");

        let auto = args.auto || args.name.is_some();

        Ok(Self {
            args: Args { auto, ..args },
            running,
            stats: DetectionStats::default(),
        })
    }

    fn get_active_baudrates(&self) -> Vec<u32> {
        // Prioritize common baud rates first (most likely to hit)
        let mut common_rates = vec![
            115200, 9600, 57600, 38400, 19200, 230400, 460800, 921600,
            1200, 2400, 4800, 14400, 28800, 76800, 128000, 256000,
        ];
        
        if self.args.highspeed {
            common_rates.extend([1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000]);
        }

        if self.args.turbo {
            // Turbo mode: only most common rates
            vec![115200, 9600, 57600, 38400, 19200, 230400, 460800, 921600]
        } else {
            common_rates
        }
    }

    fn print_baudrates(&self) {
        let rates = self.get_active_baudrates();
        println!("{}", "Supported baudrates:".bold().green());
        for (i, rate) in rates.iter().enumerate() {
            print!("{:>8}", rate);
            if (i + 1) % 6 == 0 { println!(); }
        }
        println!();
    }

    fn detect_baudrate(&mut self) -> Result<u32, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let rates = self.get_active_baudrates();
        
        println!("{}", "Starting detection...".bright_blue());
        if self.args.highspeed {
            println!("{}", "High-speed mode: Enabled".bright_magenta());
        }
        println!("Testing {} baud rates...\n", rates.len());

        for &baudrate in &rates {
            if !self.running.load(Ordering::SeqCst) {
                break;
            }

            self.stats.baudrates_tried += 1;
            print!("{} {:>7} baud... ", "Testing:".cyan(), baudrate);
            io::stdout().flush().ok();

            // Open port with short timeout for non-blocking behavior
            let port_result = serialport::new(&self.args.port, baudrate)
                .timeout(Duration::from_millis(100))
                .open();

            let mut port = match port_result {
                Ok(p) => p,
                Err(e) => {
                    println!("{}", format!("Failed to open: {}", e).red());
                    continue;
                }
            };

            // Configure port
            port.set_flow_control(serialport::FlowControl::None).ok();
            port.set_data_bits(serialport::DataBits::Eight).ok();
            port.set_parity(serialport::Parity::None).ok();
            port.set_stop_bits(serialport::StopBits::One).ok();
            port.clear(serialport::ClearBuffer::All).ok();

            // Sample data for this baud rate
            let sample_start = Instant::now();
            let mut all_bytes: Vec<u8> = Vec::new();
            let mut buffer = [0u8; 256];

            while sample_start.elapsed() < Duration::from_secs(self.args.timeout) {
                if !self.running.load(Ordering::SeqCst) {
                    break;
                }

                match port.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        all_bytes.extend_from_slice(&buffer[..n]);
                        self.stats.bytes_processed += n;
                    }
                    _ => {}
                }

                // Check if we have enough data to analyze
                if all_bytes.len() >= 50 {
                    break;
                }
            }

            if all_bytes.is_empty() {
                println!("{}", "No data".yellow());
                continue;
            }

            // Analyze the collected bytes
            let score = self.calculate_readability_score(&all_bytes);
            let preview = self.get_preview(&all_bytes);

            if !self.args.quiet {
                print!("[{}] ", preview);
            }

            if score >= 60 {
                println!("{} (score: {}%)", "MATCH!".green().bold(), score);
                self.stats.detection_time = start_time.elapsed();
                return Ok(baudrate);
            } else {
                println!("{} (score: {}%)", "low".dimmed(), score);
            }
        }

        self.stats.detection_time = start_time.elapsed();
        Err("Could not detect baud rate - no readable output found".into())
    }

    fn calculate_readability_score(&self, data: &[u8]) -> u32 {
        if data.is_empty() {
            return 0;
        }

        let mut printable = 0;
        let mut alphanumeric = 0;
        let mut common_chars = 0; // space, newline, common punctuation

        for &byte in data {
            let c = byte as char;
            
            if byte >= 0x20 && byte <= 0x7E {
                printable += 1;
            }
            if c.is_ascii_alphanumeric() {
                alphanumeric += 1;
            }
            if matches!(byte, b' ' | b'\n' | b'\r' | b'.' | b':' | b'-' | b'=' | b'[' | b']') {
                common_chars += 1;
            }
        }

        let total = data.len() as f32;
        let printable_ratio = printable as f32 / total;
        let alpha_ratio = alphanumeric as f32 / total;
        let common_ratio = common_chars as f32 / total;

        // Score: weighted combination
        // High printable ratio is most important
        // Some alphanumeric content expected
        // Common formatting chars (spaces, newlines) indicate structure
        let score = (printable_ratio * 50.0) + (alpha_ratio * 30.0) + (common_ratio * 20.0);
        
        (score.min(100.0)) as u32
    }

    fn get_preview(&self, data: &[u8]) -> String {
        let preview: String = data.iter()
            .take(30)
            .map(|&b| {
                if b >= 0x20 && b <= 0x7E {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        preview
    }

    fn save_minicom_config(&self, baudrate: u32, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let config = format!(
            "########################################################################\n\
            # Minicom configuration file - generated by baudowl\n\
            pu port             {}\n\
            pu baudrate         {}\n\
            pu bits             8\n\
            pu parity           N\n\
            pu stopbits         1\n\
            pu rtscts           No\n\
            ########################################################################",
            self.args.port, baudrate
        );

        let config_path = format!("/etc/minicom/minirc.{}", name);
        std::fs::write(&config_path, config)?;
        println!("{}", format!("Configuration saved to {}", config_path).green());
        Ok(())
    }

    fn launch_minicom(&self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!("{}", "Launching Minicom...".bright_blue());
        Command::new("minicom")
            .arg(name)
            .spawn()?
            .wait()?;
        Ok(())
    }

    fn print_stats(&self) {
        println!("\n{}", "=== Detection Statistics ===".bold().cyan());
        println!("Baudrates tried: {}", self.stats.baudrates_tried);
        println!("Bytes processed: {}", self.stats.bytes_processed);
        println!("Detection time: {:.2?}", self.stats.detection_time);
        if self.stats.detection_time.as_secs() > 0 {
            let bytes_per_sec = self.stats.bytes_processed as f64 / self.stats.detection_time.as_secs_f64();
            println!("Processing speed: {:.2} bytes/sec", bytes_per_sec);
        }
    }

    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("{}", BANNER.bright_cyan());
        
        if self.args.baudlist {
            self.print_baudrates();
            return Ok(());
        }

        match self.detect_baudrate() {
            Ok(detected_rate) => {
                println!(
                    "\n{} {} {}",
                    "🦉 HOOT!".bold().yellow(),
                    "Detected baudrate:".bright_green(),
                    detected_rate.to_string().bold()
                );

                if let Some(name) = &self.args.name.clone() {
                    self.save_minicom_config(detected_rate, name)?;
                    self.launch_minicom(name)?;
                }
            }
            Err(e) => {
                println!("\n{} {}", "Detection failed:".red().bold(), e);
            }
        }

        self.print_stats();
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut hound = match BaudOwl::new(args) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            std::process::exit(1);
        }
    };
    hound.run()
}
