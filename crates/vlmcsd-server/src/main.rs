use std::sync::Arc;
use std::time::Duration;

use vlmcsd_kmsdata::KmsData;
use vlmcsd_network::{ServerConfig, run_server};
use vlmcsd_protocol::generate_random_epid;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut listen_addr = "0.0.0.0:1688".to_string();
    let mut timeout_secs = 30u64;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-L" | "--listen" => {
                i += 1;
                if i < args.len() {
                    listen_addr = args[i].clone();
                }
            }
            "-t" | "--timeout" => {
                i += 1;
                if i < args.len() {
                    timeout_secs = args[i].parse().unwrap_or(30);
                }
            }
            "-h" | "--help" => {
                print_usage();
                return;
            }
            "-V" | "--version" => {
                println!("vlmcsd-rs {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                print_usage();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let kms_data = KmsData::load_embedded();

    // Generate initial ePIDs
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    eprintln!("vlmcsd-rs {} starting", env!("CARGO_PKG_VERSION"));
    for idx in 0..kms_data.header.csvlk_count as usize {
        let epid = generate_random_epid(&kms_data, idx, seed.wrapping_add(idx as u64));
        eprintln!("  ePID[{}]: {}", idx, epid);
    }

    let config = ServerConfig {
        listen_addr,
        timeout: Duration::from_secs(timeout_secs),
    };

    let kms_data = Arc::new(kms_data);
    if let Err(e) = run_server(&config, kms_data) {
        eprintln!("Fatal: {}", e);
        std::process::exit(1);
    }
}

fn print_usage() {
    eprintln!("Usage: vlmcsd [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -L, --listen <ADDR>    Listen address (default: 0.0.0.0:1688)");
    eprintln!("  -t, --timeout <SECS>   Connection timeout (default: 30)");
    eprintln!("  -V, --version          Print version");
    eprintln!("  -h, --help             Print help");
}
