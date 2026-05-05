mod rpc_client;

use std::net::TcpStream;
use std::time::Duration;

use vlmcsd_kmsdata::KmsData;
use vlmcsd_protocol::{create_request_v4, create_request_v6, decrypt_response_v6, get_random_bytes};
use vlmcsd_types::{FileTime, Guid, Request, VersionInfo};

use rpc_client::{rpc_bind_client, rpc_send_request};

const DEFAULT_HOST: &str = "127.0.0.1:1688";
const DEFAULT_BINDING_EXPIRATION: u32 = 43200;
const DEFAULT_LICENSE_STATUS: u32 = 0x02;
const DEFAULT_N_POLICY: u32 = 25;

struct ClientConfig {
    host: String,
    product_index: Option<usize>,
    force_version: Option<u16>,
    verbose: bool,
    n_requests: u32,
    workstation_name: Option<String>,
    timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            host: DEFAULT_HOST.to_string(),
            product_index: None,
            force_version: None,
            verbose: false,
            n_requests: 1,
            workstation_name: None,
            timeout: Duration::from_secs(30),
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let config = match parse_args(&args) {
        Some(c) => c,
        None => return,
    };

    let kms_data = KmsData::load_embedded();

    let (app_guid, kms_guid, sku_guid, major_ver, n_count_policy) =
        resolve_product(&kms_data, &config);

    let major_ver = config.force_version.unwrap_or(major_ver);

    let request = build_request(
        major_ver,
        &app_guid,
        &kms_guid,
        &sku_guid,
        n_count_policy,
        &config,
    );

    if config.verbose {
        print_request_info(&request, &kms_data);
    }

    let mut stream = match TcpStream::connect(&config.host) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Fatal: Cannot connect to {}: {}", config.host, e);
            std::process::exit(1);
        }
    };

    let _ = stream.set_read_timeout(Some(config.timeout));
    let _ = stream.set_write_timeout(Some(config.timeout));

    if let Err(e) = rpc_bind_client(&mut stream) {
        eprintln!("Fatal: RPC bind failed: {}", e);
        std::process::exit(1);
    }

    if config.verbose {
        eprintln!("RPC bind successful");
    }

    for req_num in 0..config.n_requests {
        if config.n_requests > 1 {
            eprint!("Sending activation request {} of {} (KMS V{}) ", req_num + 1, config.n_requests, major_ver);
        } else {
            eprint!("Sending activation request (KMS V{}) ", major_ver);
        }

        let raw_request = if major_ver < 5 {
            create_request_v4(&request)
        } else {
            create_request_v6(&request)
        };

        match rpc_send_request(&mut stream, &raw_request) {
            Ok(response_data) => {
                eprintln!("-> success");
                if let Err(e) = process_response(&response_data, &raw_request, major_ver, config.verbose) {
                    eprintln!("Warning: {}", e);
                }
            }
            Err(e) => {
                eprintln!("-> failed");
                eprintln!("Error: {}", e);
                if config.n_requests == 1 {
                    std::process::exit(1);
                }
            }
        }
    }
}

fn parse_args(args: &[String]) -> Option<ClientConfig> {
    let mut config = ClientConfig::default();
    let mut i = 1;
    let mut host_set = false;

    while i < args.len() {
        match args[i].as_str() {
            "-4" => {
                config.force_version = Some(4);
            }
            "-5" => {
                config.force_version = Some(5);
            }
            "-6" => {
                config.force_version = Some(6);
            }
            "-v" => {
                config.verbose = true;
            }
            "-l" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: -l requires an argument");
                    print_usage();
                    return None;
                }
                if let Ok(idx) = args[i].parse::<usize>() {
                    config.product_index = Some(idx.saturating_sub(1));
                } else {
                    eprintln!("Error: -l requires a numeric product index");
                    eprintln!("Use -x to list available products");
                    return None;
                }
            }
            "-n" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: -n requires an argument");
                    return None;
                }
                config.n_requests = args[i].parse().unwrap_or(1);
            }
            "-w" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: -w requires an argument");
                    return None;
                }
                config.workstation_name = Some(args[i].clone());
            }
            "-t" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: -t requires an argument");
                    return None;
                }
                // timeout in seconds
                let _ = args[i].parse::<u64>().map(|s| config.timeout = Duration::from_secs(s));
            }
            "-x" => {
                show_products();
                return None;
            }
            "-V" | "--version" => {
                println!("vlmcs-rs {}", env!("CARGO_PKG_VERSION"));
                return None;
            }
            "-h" | "--help" => {
                print_usage();
                return None;
            }
            other => {
                if other.starts_with('-') {
                    eprintln!("Unknown option: {}", other);
                    print_usage();
                    return None;
                }
                if !host_set {
                    config.host = other.to_string();
                    if !config.host.contains(':') {
                        config.host.push_str(":1688");
                    }
                    host_set = true;
                }
            }
        }
        i += 1;
    }

    Some(config)
}

fn print_usage() {
    eprintln!("Usage: vlmcs [options] [<host>[:<port>]]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -v               Be verbose");
    eprintln!("  -l <N>           Product index (use -x to list)");
    eprintln!("  -4               Force V4 protocol");
    eprintln!("  -5               Force V5 protocol");
    eprintln!("  -6               Force V6 protocol");
    eprintln!("  -n <count>       Number of requests to send");
    eprintln!("  -w <name>        Custom workstation name");
    eprintln!("  -t <secs>        Connection timeout (default: 30)");
    eprintln!("  -x               Show valid products");
    eprintln!("  -V, --version    Print version");
    eprintln!("  -h, --help       Print help");
    eprintln!();
    eprintln!("<host>:  KMS server (default: 127.0.0.1)");
    eprintln!("<port>:  TCP port (default: 1688)");
}

fn show_products() {
    let kms_data = KmsData::load_embedded();
    println!("Available products:\n");
    for (i, item) in kms_data.sku_items.iter().enumerate() {
        let name = kms_data.get_string(item.name_offset);
        println!("  {:3} = {}", i + 1, name);
    }
}

fn resolve_product(kms_data: &KmsData, config: &ClientConfig) -> (Guid, Guid, Guid, u16, u32) {
    let idx = config.product_index.unwrap_or(0);

    if idx >= kms_data.sku_items.len() {
        eprintln!("Error: product index {} out of range (max {})", idx + 1, kms_data.sku_items.len());
        std::process::exit(1);
    }

    let sku = &kms_data.sku_items[idx];
    let sku_guid = sku.guid;

    let kms_guid = if (sku.kms_index as i32) < kms_data.header.kms_item_count {
        kms_data.kms_items[sku.kms_index as usize].guid
    } else {
        Guid::ZERO
    };

    let app_guid = if (sku.app_index as i32) < kms_data.header.app_item_count {
        kms_data.app_items[sku.app_index as usize].guid
    } else {
        Guid::ZERO
    };

    let major_ver = match sku.protocol_version {
        0 => 6u16,
        v => v as u16,
    };

    let n_count_policy = if sku.n_count_policy == 0 {
        DEFAULT_N_POLICY
    } else {
        sku.n_count_policy as u32
    };

    (app_guid, kms_guid, sku_guid, major_ver, n_count_policy)
}

fn build_request(
    major_ver: u16,
    app_guid: &Guid,
    kms_guid: &Guid,
    sku_guid: &Guid,
    n_count_policy: u32,
    config: &ClientConfig,
) -> Request {
    let cmid = random_uuid_v4();

    let mut workstation_name = [0u16; 64];
    let ws_str = config.workstation_name.as_deref().unwrap_or("WORKSTATION");
    for (i, ch) in ws_str.encode_utf16().take(63).enumerate() {
        workstation_name[i] = ch;
    }

    Request {
        version: VersionInfo { major_ver, minor_ver: 0 },
        vm_info: 0,
        license_status: DEFAULT_LICENSE_STATUS,
        binding_expiration: DEFAULT_BINDING_EXPIRATION,
        app_id: *app_guid,
        act_id: *sku_guid,
        kms_id: *kms_guid,
        cmid,
        n_policy: n_count_policy,
        client_time: FileTime::now(),
        cmid_prev: Guid::ZERO,
        workstation_name,
    }
}

fn random_uuid_v4() -> Guid {
    let mut bytes = [0u8; 16];
    get_random_bytes(&mut bytes);
    // Set UUID version 4 and variant bits
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    Guid::from_le_bytes(&bytes)
}

fn print_request_info(request: &Request, kms_data: &KmsData) {
    eprintln!("\nRequest Parameters");
    eprintln!("==================");
    eprintln!("  Protocol version: {}.{}", request.version.major_ver, request.version.minor_ver);
    eprintln!("  Client Machine ID: {}", request.cmid);
    eprintln!("  Application ID: {}", request.app_id);

    if let Some((_, name)) = kms_data.find_product(&request.app_id) {
        eprintln!("    ({})", name);
    }

    eprintln!("  Activation ID: {}", request.act_id);
    if let Some((_, name)) = kms_data.find_product(&request.act_id) {
        eprintln!("    ({})", name);
    }

    eprintln!("  KMS ID: {}", request.kms_id);
    if let Some((_, name)) = kms_data.find_product(&request.kms_id) {
        eprintln!("    ({})", name);
    }

    eprintln!("  N Count Policy: {}", request.n_policy);
    eprintln!("  License Status: {}", request.license_status);
    eprintln!("  Binding Expiration: {} minutes", request.binding_expiration);
    eprintln!();
}

fn process_response(
    response_data: &[u8],
    raw_request: &[u8],
    major_ver: u16,
    verbose: bool,
) -> Result<(), String> {
    if major_ver < 5 {
        // V4: response is plaintext ResponseBase + 16-byte CMAC
        parse_and_display_response(response_data, verbose)
    } else {
        // V5/V6: decrypt first
        let decrypted = decrypt_response_v6(response_data, raw_request)?;
        // Skip IV (first 16 bytes)
        if decrypted.len() < 16 {
            return Err("decrypted response too short".to_string());
        }
        parse_and_display_response(&decrypted[16..], verbose)
    }
}

fn parse_and_display_response(data: &[u8], verbose: bool) -> Result<(), String> {
    // Response wire: Version(4) + PidSize(4) + Pid(variable) + CMID(16) + Time(8) + Count(4) + VLActivation(4) + VLRenewal(4)
    if data.len() < 8 {
        return Err("response too short".to_string());
    }

    let version = VersionInfo::from_le_bytes(data[0..4].try_into().unwrap());
    let pid_size = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;

    if data.len() < 8 + pid_size + 16 + 8 + 4 + 4 + 4 {
        return Err("response truncated".to_string());
    }

    let pid_data = &data[8..8 + pid_size];
    let epid: String = pid_data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&ch| ch != 0)
        .map(|ch| char::from_u32(ch as u32).unwrap_or('?'))
        .collect();

    let off = 8 + pid_size;
    let _cmid = Guid::from_le_bytes(data[off..off + 16].try_into().unwrap());
    let _client_time = u64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap());
    let count = u32::from_le_bytes(data[off + 24..off + 28].try_into().unwrap());
    let vl_activation = u32::from_le_bytes(data[off + 28..off + 32].try_into().unwrap());
    let vl_renewal = u32::from_le_bytes(data[off + 32..off + 36].try_into().unwrap());

    if verbose {
        eprintln!("\nResponse Parameters");
        eprintln!("===================");
        eprintln!("  KMS Protocol Version: {}.{}", version.major_ver, version.minor_ver);
    }

    println!("ePID: {}", epid);
    println!("Client Count: {}", count);
    println!("VL Activation Interval: {} minutes", vl_activation);
    println!("VL Renewal Interval: {} minutes", vl_renewal);

    Ok(())
}
