use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use vlmcsd_kmsdata::KmsData;
use vlmcsd_rpc::rpc_server;

pub struct ServerConfig {
    pub listen_addr: String,
    pub timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen_addr: "0.0.0.0:1688".to_string(),
            timeout: Duration::from_secs(30),
        }
    }
}

pub fn run_server(config: &ServerConfig, kms_data: Arc<KmsData>) -> io::Result<()> {
    run_server_with_shutdown(config, kms_data, None)
}

pub fn run_server_with_shutdown(
    config: &ServerConfig,
    kms_data: Arc<KmsData>,
    shutdown: Option<Arc<AtomicBool>>,
) -> io::Result<()> {
    let listener = TcpListener::bind(&config.listen_addr)?;
    eprintln!("Listening on {}", config.listen_addr);

    if shutdown.is_some() {
        listener.set_nonblocking(true)?;
    }

    loop {
        if let Some(ref flag) = shutdown {
            if flag.load(Ordering::Relaxed) {
                eprintln!("Shutting down");
                return Ok(());
            }
        }

        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let kms = Arc::clone(&kms_data);
                let timeout = config.timeout;
                thread::spawn(move || {
                    handle_client(stream, &kms, timeout);
                });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("Accept error: {}", e);
            }
        }
    }
}

fn handle_client(mut stream: TcpStream, kms_data: &KmsData, timeout: Duration) {
    let peer = stream.peer_addr().ok();
    if let Some(ref addr) = peer {
        eprintln!("Connection from {}", addr);
    }

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    if let Err(e) = rpc_server(&mut stream, kms_data) {
        if e.kind() != io::ErrorKind::UnexpectedEof
            && e.kind() != io::ErrorKind::ConnectionReset
            && e.kind() != io::ErrorKind::BrokenPipe
        {
            eprintln!("Client error: {}", e);
        }
    }

    if let Some(ref addr) = peer {
        eprintln!("Disconnected {}", addr);
    }
}
