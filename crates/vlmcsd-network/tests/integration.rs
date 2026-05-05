use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::io::{Read, Write};

use vlmcsd_kmsdata::KmsData;
use vlmcsd_network::{ServerConfig, run_server};
use vlmcsd_protocol::{create_request_v4, create_request_v6};
use vlmcsd_rpc::{
    RpcHeader, RPC_HEADER_SIZE, RPC_PT_BIND_REQ, RPC_PT_BIND_ACK,
    RPC_PT_REQUEST, RPC_PT_RESPONSE, RPC_PF_FIRST, RPC_PF_LAST,
};
use vlmcsd_types::{FileTime, Guid, Request, VersionInfo};

const INTERFACE_UUID: [u8; 16] = [
    0x75, 0x21, 0xC8, 0x51, 0x4E, 0x84, 0x50, 0x47,
    0xB0, 0xD8, 0xEC, 0x25, 0x55, 0x55, 0xBC, 0x06,
];

const TRANSFER_SYNTAX_NDR32: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
    0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];

fn make_request(major_ver: u16) -> Request {
    let mut workstation_name = [0u16; 64];
    for (i, ch) in "TEST-PC".encode_utf16().enumerate() {
        workstation_name[i] = ch;
    }
    Request {
        version: VersionInfo { major_ver, minor_ver: 0 },
        vm_info: 0,
        license_status: 2,
        binding_expiration: 43200,
        app_id: Guid::ZERO,
        act_id: Guid::ZERO,
        kms_id: Guid::ZERO,
        cmid: Guid::ZERO,
        n_policy: 25,
        client_time: FileTime::from_unix_secs(1700000000),
        cmid_prev: Guid::ZERO,
        workstation_name,
    }
}

fn rpc_bind(stream: &mut TcpStream) {
    let mut payload = Vec::new();
    payload.extend_from_slice(&5840u16.to_le_bytes());
    payload.extend_from_slice(&5840u16.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(&INTERFACE_UUID);
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&TRANSFER_SYNTAX_NDR32);
    payload.extend_from_slice(&2u32.to_le_bytes());

    let total_len = RPC_HEADER_SIZE + payload.len();
    let header = RpcHeader {
        version_major: 5, version_minor: 0,
        packet_type: RPC_PT_BIND_REQ,
        packet_flags: RPC_PF_FIRST | RPC_PF_LAST,
        data_representation: 0x00000010,
        frag_length: total_len as u16,
        auth_length: 0, call_id: 1,
    };

    let mut out = Vec::with_capacity(total_len);
    header.write_to(&mut out);
    out.extend_from_slice(&payload);
    stream.write_all(&out).unwrap();

    let resp = RpcHeader::read_from(stream).unwrap();
    assert_eq!(resp.packet_type, RPC_PT_BIND_ACK);
    let mut ack = vec![0u8; resp.frag_length as usize - RPC_HEADER_SIZE];
    stream.read_exact(&mut ack).unwrap();
}

fn rpc_request(stream: &mut TcpStream, kms_request: &[u8]) -> Vec<u8> {
    let ndr_size: usize = 8;
    let alloc_hint = (ndr_size + kms_request.len()) as u32;

    let mut payload = Vec::new();
    payload.extend_from_slice(&alloc_hint.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&(kms_request.len() as u32).to_le_bytes());
    payload.extend_from_slice(&(kms_request.len() as u32).to_le_bytes());
    payload.extend_from_slice(kms_request);

    let total_len = RPC_HEADER_SIZE + payload.len();
    let header = RpcHeader {
        version_major: 5, version_minor: 0,
        packet_type: RPC_PT_REQUEST,
        packet_flags: RPC_PF_FIRST | RPC_PF_LAST,
        data_representation: 0x00000010,
        frag_length: total_len as u16,
        auth_length: 0, call_id: 2,
    };

    let mut out = Vec::with_capacity(total_len);
    header.write_to(&mut out);
    out.extend_from_slice(&payload);
    stream.write_all(&out).unwrap();

    let resp = RpcHeader::read_from(stream).unwrap();
    assert_eq!(resp.packet_type, RPC_PT_RESPONSE);
    let payload_len = resp.frag_length as usize - RPC_HEADER_SIZE;
    let mut resp_payload = vec![0u8; payload_len];
    stream.read_exact(&mut resp_payload).unwrap();

    let data_length = u32::from_le_bytes(resp_payload[8..12].try_into().unwrap()) as usize;
    resp_payload[20..20 + data_length].to_vec()
}

fn start_server_on(port: u16) {
    let config = ServerConfig {
        listen_addr: format!("127.0.0.1:{}", port),
        timeout: Duration::from_secs(5),
    };
    let kms_data = Arc::new(KmsData::load_embedded());
    thread::spawn(move || { let _ = run_server(&config, kms_data); });

    for _ in 0..50 {
        if TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("server did not start");
}

#[test]
fn v4_roundtrip() {
    let port = 31688u16;
    start_server_on(port);

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    rpc_bind(&mut stream);

    let raw = create_request_v4(&make_request(4));
    let response = rpc_request(&mut stream, &raw);

    assert!(response.len() > 8);
    let ver = VersionInfo::from_le_bytes(response[0..4].try_into().unwrap());
    assert_eq!(ver.major_ver, 4);
}

#[test]
fn v5_roundtrip() {
    let port = 31689u16;
    start_server_on(port);

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    rpc_bind(&mut stream);

    let raw = create_request_v6(&make_request(5));
    let response = rpc_request(&mut stream, &raw);
    assert!(response.len() > 20);
}

#[test]
fn v6_roundtrip() {
    let port = 31690u16;
    start_server_on(port);

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    rpc_bind(&mut stream);

    let raw = create_request_v6(&make_request(6));
    let response = rpc_request(&mut stream, &raw);
    assert!(response.len() > 20);
}
