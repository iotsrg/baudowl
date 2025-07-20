use std::{
    io::{self, Read, Write},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use clap::Parser;
use serialport::SerialPort;
use ctrlc;
use colored::*;

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

struct baudowl {
    args: Args,
    base_baudrates: Vec<u32>,
    highspeed_baudrates: Vec<u32>,
    running: Arc<AtomicBool>,
    stats: DetectionStats,
    current_baudrate_index: usize,
}

#[derive(Default)]
struct DetectionStats {
    bytes_processed: usize,
    baudrates_tried: usize,
    detection_time: Duration,
}

impl baudowl {
    fn new(args: Args) -> Self {
        let base_baudrates = vec![
            110, 150, 300, 600, 800, 1200, 1600, 1800, 2400, 2604, 3200, 4800,
            5208, 6400, 9600, 9606, 10417, 12800, 14400, 15625, 14406, 19200, 19211,
            25600, 26042, 28800, 31250, 38400, 38422, 52083, 57600, 57692, 78600,
            104167, 115200, 115384, 156250, 230400, 230769, 256000, 312500, 460800,
            461538, 921600, 923076,
        ];

        let highspeed_baudrates = vec![
            1_000_000,
            1_500_000,
            3_000_000,
            4_000_000,
        ];

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");

        let auto = args.auto || args.name.is_some();

        Self {
            args: Args { auto, ..args },
            base_baudrates,
            highspeed_baudrates,
            running,
            stats: DetectionStats::default(),
            current_baudrate_index: 0,
        }
    }

    fn get_active_baudrates(&self) -> Vec<u32> {
        let mut rates = self.base_baudrates.clone();
        
        if self.args.highspeed {
            rates.extend(self.highspeed_baudrates.iter().cloned());
        }

        if self.args.turbo {
            rates.retain(|&r| self.is_common_baudrate(r));
        }

        rates
    }

    fn is_common_baudrate(&self, rate: u32) -> bool {
        match rate {
            300 | 1200 | 2400 | 4800 | 9600 | 19200 | 38400 | 57600 |
            115200 | 230400 | 460800 | 921600 | 1_000_000 | 1_500_000 => true,
            _ => false,
        }
    }

    fn print_baudrates(&self) {
        println!("{}", "Standard baudrates:".bold().green());
        for (i, rate) in self.base_baudrates.iter().enumerate() {
            print!("{:8}", rate);
            if (i + 1) % 6 == 0 { println!(); }
        }

        if self.args.highspeed {
            println!("\n\n{}", "Ultra-high baudrates:".bold().blue());
            for rate in &self.highspeed_baudrates {
                print!("{:8}", rate);
            }
        }
        println!();
    }

    fn open_serial_port(&self, baudrate: u32) -> Result<Box<dyn SerialPort>, serialport::Error> {
        let mut port = serialport::new(&self.args.port, baudrate)
            .timeout(Duration::from_secs(self.args.timeout))
            .open()?;
            
        port.set_flow_control(serialport::FlowControl::None)?;
        port.set_data_bits(serialport::DataBits::Eight)?;
        port.set_parity(serialport::Parity::None)?;
        port.set_stop_bits(serialport::StopBits::One)?;
        
        Ok(port)
    }

    fn next_baudrate(&mut self, port: &mut Box<dyn SerialPort>, rates: &[u32], direction: i32) {
        self.stats.baudrates_tried += 1;
        self.current_baudrate_index = (self.current_baudrate_index as i32 + direction) as usize;
        
        if self.current_baudrate_index >= rates.len() {
            self.current_baudrate_index = 0;
        } else if (self.current_baudrate_index as i32) < 0 {
            self.current_baudrate_index = rates.len() - 1;
        }

        port.clear(serialport::ClearBuffer::All).ok();
        port.set_baud_rate(rates[self.current_baudrate_index]).ok();
    }

    fn detect_baudrate(&mut self) -> Result<u32, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let rates = self.get_active_baudrates();
        let mut port = self.open_serial_port(rates[0])?;
        
        if !self.args.auto {
            let running = self.running.clone();
            thread::spawn(move || {
                let mut input = String::new();
                while running.load(Ordering::SeqCst) {
                    io::stdin().read_line(&mut input).ok();
                    input.clear();
                }
            });
        }

        let mut buffer = [0; 1024];
        let mut count = 0;
        let mut whitespace = 0;
        let mut punctuation = 0;
        let mut vowels = 0;
        let mut start_time_current = Instant::now();
        
        let punctuation_chars = ['.', ',', ':', ';', '?', '!'];
        let vowel_chars = ['a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U'];

        println!("{}", "Starting detection...".bright_blue());
        if self.args.highspeed {
            println!("{}", "High-speed mode: Enabled".bright_magenta());
        }

        loop {
            if start_time_current.elapsed() >= Duration::from_secs(self.args.timeout) {
                self.next_baudrate(&mut port, &rates, -1);
                start_time_current = Instant::now();
                count = 0;
                whitespace = 0;
                punctuation = 0;
                vowels = 0;
            }

            match port.read(&mut buffer) {
                Ok(n) => {
                    self.stats.bytes_processed += n;
                    
                    for &byte in &buffer[..n] {
                        let c = byte as char;
                        
                        if !self.args.quiet {
                            print!("{}", c);
                            io::stdout().flush().ok();
                        }

                        if c.is_ascii() && !c.is_ascii_control() {
                            if c.is_whitespace() {
                                whitespace += 1;
                            } else if punctuation_chars.contains(&c) {
                                punctuation += 1;
                            } else if vowel_chars.contains(&c) {
                                vowels += 1;
                            }
                            count += 1;
                        }

                        if count >= self.args.threshold && whitespace > 0 && punctuation > 0 && vowels > 0 {
                            self.stats.detection_time = start_time.elapsed();
                            return Ok(rates[self.current_baudrate_index]);
                        }
                    }
                }
                _ => continue,
            }

            if !self.running.load(Ordering::SeqCst) {
                break;
            }
        }

        self.stats.detection_time = start_time.elapsed();
        Ok(rates[self.current_baudrate_index])
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

        let detected_rate = self.detect_baudrate()?;
        
        println!(
            "\n{} {} {}",
            "🐕 WOOF!".bold().yellow(),
            "Detected baudrate:".bright_green(),
            detected_rate.to_string().bold()
        );

        if let Some(name) = &self.args.name {
            self.save_minicom_config(detected_rate, name)?;
            self.launch_minicom(name)?;
        }

        self.print_stats();
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut hound = baudowl::new(args);
    hound.run()
}
