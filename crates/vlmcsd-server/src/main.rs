use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use vlmcsd_kmsdata::KmsData;
use vlmcsd_network::{ServerConfig, run_server_with_shutdown};
use vlmcsd_protocol::generate_random_epid;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut listen_addr = "0.0.0.0:1688".to_string();
    let mut timeout_secs = 30u64;
    let mut daemonize = false;
    let mut pid_file: Option<String> = None;

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
            "-D" | "--daemon" => {
                daemonize = true;
            }
            "-p" | "--pid-file" => {
                i += 1;
                if i < args.len() {
                    pid_file = Some(args[i].clone());
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

    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    eprintln!("vlmcsd-rs {} starting", env!("CARGO_PKG_VERSION"));
    for idx in 0..kms_data.header.csvlk_count as usize {
        let epid = generate_random_epid(&kms_data, idx, seed.wrapping_add(idx as u64));
        eprintln!("  ePID[{}]: {}", idx, epid);
    }

    if daemonize {
        #[cfg(unix)]
        {
            daemonize_process();
        }
        #[cfg(not(unix))]
        {
            eprintln!("Warning: daemon mode not supported on this platform");
        }
    }

    if let Some(ref path) = pid_file {
        write_pid_file(path);
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    install_signal_handlers(Arc::clone(&shutdown));

    let config = ServerConfig {
        listen_addr,
        timeout: Duration::from_secs(timeout_secs),
    };

    let kms_data = Arc::new(kms_data);
    if let Err(e) = run_server_with_shutdown(&config, kms_data, Some(shutdown)) {
        eprintln!("Fatal: {}", e);
        cleanup_pid_file(&pid_file);
        std::process::exit(1);
    }

    cleanup_pid_file(&pid_file);
}

fn install_signal_handlers(shutdown: Arc<AtomicBool>) {
    #[cfg(unix)]
    {
        use std::thread;

        let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&raw mut sigset);
            libc::sigaddset(&raw mut sigset, libc::SIGINT);
            libc::sigaddset(&raw mut sigset, libc::SIGTERM);
            libc::pthread_sigmask(libc::SIG_BLOCK, &sigset, std::ptr::null_mut());
        }

        thread::spawn(move || {
            loop {
                let mut sig: libc::c_int = 0;
                let ret = unsafe { libc::sigwait(&sigset, &raw mut sig) };
                if ret == 0 {
                    eprintln!("Received signal {}, shutting down...", sig);
                    shutdown.store(true, Ordering::Relaxed);
                    break;
                }
            }
        });
    }

    #[cfg(not(unix))]
    {
        let _ = shutdown;
    }
}

#[cfg(unix)]
fn daemonize_process() {
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            eprintln!("Fatal: fork() failed");
            std::process::exit(1);
        }
        if pid > 0 {
            std::process::exit(0);
        }

        if libc::setsid() < 0 {
            eprintln!("Fatal: setsid() failed");
            std::process::exit(1);
        }

        // Second fork to prevent acquiring a controlling terminal
        let pid = libc::fork();
        if pid < 0 {
            eprintln!("Fatal: fork() failed");
            std::process::exit(1);
        }
        if pid > 0 {
            std::process::exit(0);
        }

        // Redirect stdin/stdout/stderr to /dev/null
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, 0);
            libc::dup2(devnull, 1);
            libc::dup2(devnull, 2);
            if devnull > 2 {
                libc::close(devnull);
            }
        }
    }
}

fn write_pid_file(path: &str) {
    use std::fs;
    let pid = std::process::id();
    if let Err(e) = fs::write(path, format!("{}\n", pid)) {
        eprintln!("Warning: cannot write PID file {}: {}", path, e);
    }
}

fn cleanup_pid_file(pid_file: &Option<String>) {
    if let Some(path) = pid_file {
        let _ = std::fs::remove_file(path);
    }
}

fn print_usage() {
    eprintln!("Usage: vlmcsd [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -L, --listen <ADDR>    Listen address (default: 0.0.0.0:1688)");
    eprintln!("  -t, --timeout <SECS>   Connection timeout (default: 30)");
    eprintln!("  -D, --daemon           Run as daemon (Unix only)");
    eprintln!("  -p, --pid-file <PATH>  Write PID to file");
    eprintln!("  -V, --version          Print version");
    eprintln!("  -h, --help             Print help");
}
