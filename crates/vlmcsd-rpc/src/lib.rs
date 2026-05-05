mod header;
mod bind;
mod request;

pub use header::*;
pub use bind::*;
use vlmcsd_kmsdata::KmsData;
use vlmcsd_protocol::{create_response_v4, create_response_v6};

use std::io::{self, Read, Write};
use std::net::TcpStream;

pub fn rpc_server(stream: &mut TcpStream, kms_data: &KmsData) -> io::Result<()> {
    let mut ndr_ctx: u16 = RPC_INVALID_CTX;
    let mut ndr64_ctx: u16 = RPC_INVALID_CTX;

    loop {
        let header = match RpcHeader::read_from(stream) {
            Ok(h) => h,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };

        let payload_len = header.frag_length as usize - RPC_HEADER_SIZE;
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload)?;

        let response = match header.packet_type {
            RPC_PT_BIND_REQ | RPC_PT_ALTERCONTEXT_REQ => {
                handle_bind(&payload, &mut ndr_ctx, &mut ndr64_ctx, &header)?
            }
            RPC_PT_REQUEST => {
                handle_request(&payload, kms_data, ndr_ctx, ndr64_ctx)?
            }
            _ => return Ok(()),
        };

        let resp_type = match header.packet_type {
            RPC_PT_BIND_REQ => RPC_PT_BIND_ACK,
            RPC_PT_ALTERCONTEXT_REQ => RPC_PT_ALTERCONTEXT_ACK,
            RPC_PT_REQUEST => RPC_PT_RESPONSE,
            _ => return Ok(()),
        };

        let total_len = RPC_HEADER_SIZE + response.len();
        let resp_header = RpcHeader {
            version_major: 5,
            version_minor: 0,
            packet_type: resp_type,
            packet_flags: RPC_PF_FIRST | RPC_PF_LAST,
            data_representation: 0x00000010, // LE, ASCII, IEEE
            frag_length: total_len as u16,
            auth_length: 0,
            call_id: header.call_id,
        };

        let mut out = Vec::with_capacity(total_len);
        resp_header.write_to(&mut out);
        out.extend_from_slice(&response);
        stream.write_all(&out)?;
    }
}

fn handle_request(
    payload: &[u8],
    kms_data: &KmsData,
    _ndr_ctx: u16,
    ndr64_ctx: u16,
) -> io::Result<Vec<u8>> {
    if payload.len() < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "request too short"));
    }

    let _alloc_hint = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    let context_id = u16::from_le_bytes(payload[4..6].try_into().unwrap());
    let _opnum = u16::from_le_bytes(payload[6..8].try_into().unwrap());

    let is_ndr64 = context_id == ndr64_ctx && ndr64_ctx != RPC_INVALID_CTX;

    let (data_offset, _ndr_header_size) = if is_ndr64 {
        // NDR64: DataLength(8) + DataSizeIs(8) = 16 bytes
        if payload.len() < 8 + 16 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "ndr64 header too short"));
        }
        (8 + 16, 16usize)
    } else {
        // NDR32: DataLength(4) + DataSizeIs(4) = 8 bytes
        if payload.len() < 8 + 8 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "ndr32 header too short"));
        }
        (8 + 8, 8usize)
    };

    let kms_request_data = &payload[data_offset..];

    if kms_request_data.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "kms data too short"));
    }

    let version = u32::from_le_bytes(kms_request_data[0..4].try_into().unwrap());
    let major_ver = (version >> 16) as u16;

    let kms_response = match major_ver {
        4 => create_response_v4(kms_request_data, kms_data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("v4 error: 0x{:08x}", e)))?,
        5 | 6 => create_response_v6(kms_request_data, kms_data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("v6 error: 0x{:08x}", e)))?,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported KMS version")),
    };

    // Build RPC response
    let response_size = kms_response.len() as u32;
    let mut rpc_response = Vec::new();

    // AllocHint
    let ndr_resp_size = if is_ndr64 { 24 } else { 12 };
    let alloc = ndr_resp_size + response_size + 4; // +4 for return code
    let padded_alloc = alloc + ((!alloc + 1) & 3); // pad to 4-byte align
    rpc_response.extend_from_slice(&padded_alloc.to_le_bytes());

    // ContextId
    rpc_response.extend_from_slice(&context_id.to_le_bytes());
    // CancelCount + Pad1
    rpc_response.extend_from_slice(&[0u8, 0u8]);

    if is_ndr64 {
        // NDR64: DataLength, DataSizeMax, DataSizeIs
        rpc_response.extend_from_slice(&(response_size as u64).to_le_bytes());
        rpc_response.extend_from_slice(&0x00020000u64.to_le_bytes());
        rpc_response.extend_from_slice(&(response_size as u64).to_le_bytes());
    } else {
        // NDR32: DataLength, DataSizeMax, DataSizeIs
        rpc_response.extend_from_slice(&response_size.to_le_bytes());
        rpc_response.extend_from_slice(&0x00020000u32.to_le_bytes());
        rpc_response.extend_from_slice(&response_size.to_le_bytes());
    }

    // KMS response data
    rpc_response.extend_from_slice(&kms_response);

    // Return code (0 = success)
    rpc_response.extend_from_slice(&0u32.to_le_bytes());

    // Pad to 4-byte alignment
    let pad = (4 - (rpc_response.len() % 4)) % 4;
    rpc_response.extend_from_slice(&vec![0u8; pad]);

    Ok(rpc_response)
}
