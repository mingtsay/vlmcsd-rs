use std::io::{self, Read, Write};
use std::net::TcpStream;

use vlmcsd_rpc::{
    RpcHeader, RPC_HEADER_SIZE, RPC_PT_BIND_REQ, RPC_PT_BIND_ACK,
    RPC_PT_REQUEST, RPC_PT_RESPONSE, RPC_PF_FIRST, RPC_PF_LAST,
};

const INTERFACE_UUID: [u8; 16] = [
    0x75, 0x21, 0xC8, 0x51, 0x4E, 0x84, 0x50, 0x47,
    0xB0, 0xD8, 0xEC, 0x25, 0x55, 0x55, 0xBC, 0x06,
];

const TRANSFER_SYNTAX_NDR32: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
    0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];

pub fn rpc_bind_client(stream: &mut TcpStream) -> io::Result<()> {
    let mut payload = Vec::new();

    // MaxXmitFrag
    payload.extend_from_slice(&5840u16.to_le_bytes());
    // MaxRecvFrag
    payload.extend_from_slice(&5840u16.to_le_bytes());
    // AssocGroup
    payload.extend_from_slice(&0u32.to_le_bytes());
    // NumCtxItems = 1 (NDR32 only for simplicity)
    payload.extend_from_slice(&1u32.to_le_bytes());

    // CtxItem[0]: NDR32
    payload.extend_from_slice(&0u16.to_le_bytes()); // ContextId = 0
    payload.extend_from_slice(&1u16.to_le_bytes()); // NumTransItems
    payload.extend_from_slice(&INTERFACE_UUID);     // InterfaceUUID
    payload.extend_from_slice(&1u16.to_le_bytes()); // VerMajor
    payload.extend_from_slice(&0u16.to_le_bytes()); // VerMinor
    payload.extend_from_slice(&TRANSFER_SYNTAX_NDR32); // TransferSyntax
    payload.extend_from_slice(&2u32.to_le_bytes()); // SyntaxVersion

    let total_len = RPC_HEADER_SIZE + payload.len();
    let header = RpcHeader {
        version_major: 5,
        version_minor: 0,
        packet_type: RPC_PT_BIND_REQ,
        packet_flags: RPC_PF_FIRST | RPC_PF_LAST,
        data_representation: 0x00000010,
        frag_length: total_len as u16,
        auth_length: 0,
        call_id: 1,
    };

    let mut out = Vec::with_capacity(total_len);
    header.write_to(&mut out);
    out.extend_from_slice(&payload);
    stream.write_all(&out)?;

    // Read bind ack response
    let resp_header = RpcHeader::read_from(stream)?;

    if resp_header.packet_type != RPC_PT_BIND_ACK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected bind ack ({}), got {}", RPC_PT_BIND_ACK, resp_header.packet_type),
        ));
    }

    if resp_header.call_id != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bind ack call_id mismatch",
        ));
    }

    // Read and discard the bind ack payload
    let payload_len = resp_header.frag_length as usize - RPC_HEADER_SIZE;
    let mut ack_payload = vec![0u8; payload_len];
    stream.read_exact(&mut ack_payload)?;

    Ok(())
}

pub fn rpc_send_request(stream: &mut TcpStream, kms_request: &[u8]) -> io::Result<Vec<u8>> {
    // Build RPC request: AllocHint(4) + ContextId(2) + Opnum(2) + NDR32 header + data
    let ndr_header_size: usize = 8; // DataLength(4) + DataSizeIs(4)
    let alloc_hint = (ndr_header_size + kms_request.len()) as u32;

    let mut payload = Vec::new();
    // AllocHint
    payload.extend_from_slice(&alloc_hint.to_le_bytes());
    // ContextId = 0 (NDR32)
    payload.extend_from_slice(&0u16.to_le_bytes());
    // Opnum = 0
    payload.extend_from_slice(&0u16.to_le_bytes());
    // NDR32: DataLength
    payload.extend_from_slice(&(kms_request.len() as u32).to_le_bytes());
    // NDR32: DataSizeIs
    payload.extend_from_slice(&(kms_request.len() as u32).to_le_bytes());
    // KMS request data
    payload.extend_from_slice(kms_request);

    let total_len = RPC_HEADER_SIZE + payload.len();
    let header = RpcHeader {
        version_major: 5,
        version_minor: 0,
        packet_type: RPC_PT_REQUEST,
        packet_flags: RPC_PF_FIRST | RPC_PF_LAST,
        data_representation: 0x00000010,
        frag_length: total_len as u16,
        auth_length: 0,
        call_id: 2,
    };

    let mut out = Vec::with_capacity(total_len);
    header.write_to(&mut out);
    out.extend_from_slice(&payload);
    stream.write_all(&out)?;

    // Read response header
    let resp_header = RpcHeader::read_from(stream)?;

    if resp_header.packet_type != RPC_PT_RESPONSE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected response ({}), got {}", RPC_PT_RESPONSE, resp_header.packet_type),
        ));
    }

    // Read response payload
    let payload_len = resp_header.frag_length as usize - RPC_HEADER_SIZE;
    let mut resp_payload = vec![0u8; payload_len];
    stream.read_exact(&mut resp_payload)?;

    // Parse RPC response: AllocHint(4) + ContextId(2) + CancelCount(1) + Pad(1) + NDR header + data + ReturnCode(4)
    if resp_payload.len() < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "response payload too short"));
    }

    let _alloc_hint = u32::from_le_bytes(resp_payload[0..4].try_into().unwrap());
    let _context_id = u16::from_le_bytes(resp_payload[4..6].try_into().unwrap());
    let _cancel_count = resp_payload[6];

    // NDR32 header: DataLength(4) + DataSizeMax(4) + DataSizeIs(4) = 12 bytes
    let ndr_off = 8;
    if resp_payload.len() < ndr_off + 12 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "NDR header too short"));
    }

    let data_length = u32::from_le_bytes(resp_payload[ndr_off..ndr_off + 4].try_into().unwrap()) as usize;
    let data_size_max = u32::from_le_bytes(resp_payload[ndr_off + 4..ndr_off + 8].try_into().unwrap());
    let _data_size_is = u32::from_le_bytes(resp_payload[ndr_off + 8..ndr_off + 12].try_into().unwrap()) as usize;

    if data_size_max == 0 {
        // Error return from server
        let status = if resp_payload.len() >= ndr_off + 16 {
            u32::from_le_bytes(resp_payload[ndr_off + 12..ndr_off + 16].try_into().unwrap())
        } else {
            0xFFFFFFFF
        };
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("server returned error 0x{:08X}", status),
        ));
    }

    let data_start = ndr_off + 12;
    if resp_payload.len() < data_start + data_length {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "KMS response data truncated"));
    }

    Ok(resp_payload[data_start..data_start + data_length].to_vec())
}
