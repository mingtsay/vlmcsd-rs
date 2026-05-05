use std::io;
use crate::header::*;

const TRANSFER_SYNTAX_NDR32: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
    0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];

const TRANSFER_SYNTAX_NDR64: [u8; 16] = [
    0x33, 0x05, 0x71, 0x71, 0xBA, 0xBE, 0x37, 0x49,
    0x83, 0x19, 0xB5, 0xDB, 0xEF, 0x9C, 0xCC, 0x36,
];

const BIND_TIME_FEATURE_NEGOTIATION: [u8; 8] = [
    0x2C, 0x1C, 0xB7, 0x6C, 0x12, 0x98, 0x40, 0x45,
];

const INTERFACE_UUID: [u8; 16] = [
    0x75, 0x21, 0xC8, 0x51, 0x4E, 0x84, 0x50, 0x47,
    0xB0, 0xD8, 0xEC, 0x25, 0x55, 0x55, 0xBC, 0x06,
];

const RPC_BIND_ACCEPT: u16 = 0;
const RPC_BIND_NACK: u16 = 2;
const RPC_BIND_ACK: u16 = 3;

const CTX_ITEM_SIZE: usize = 44; // ContextId(2) + NumTransItems(2) + InterfaceUUID(16) + VerMajor(2) + VerMinor(2) + TransferSyntax(16) + SyntaxVersion(4)

pub fn handle_bind(
    payload: &[u8],
    ndr_ctx: &mut u16,
    ndr64_ctx: &mut u16,
    header: &RpcHeader,
) -> io::Result<Vec<u8>> {
    // Bind request: MaxXmitFrag(2) + MaxRecvFrag(2) + AssocGroup(4) + NumCtxItems(4) = 12
    if payload.len() < 12 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bind request too short"));
    }

    let max_xmit_frag = u16::from_le_bytes([payload[0], payload[1]]);
    let max_recv_frag = u16::from_le_bytes([payload[2], payload[3]]);
    let _assoc_group = u32::from_le_bytes(payload[4..8].try_into().unwrap());
    let num_ctx_items = u32::from_le_bytes(payload[8..12].try_into().unwrap()) as usize;

    let ctx_items_data = &payload[12..];
    if ctx_items_data.len() < num_ctx_items * CTX_ITEM_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bind ctx items truncated"));
    }

    // Determine if NDR64 is possible
    let mut has_ndr64 = false;
    for i in 0..num_ctx_items {
        let off = i * CTX_ITEM_SIZE;
        let transfer_syntax = &ctx_items_data[off + 24..off + 40];
        if transfer_syntax == TRANSFER_SYNTAX_NDR64 {
            has_ndr64 = true;
            break;
        }
    }

    // Build response
    let mut response = Vec::new();

    // MaxXmitFrag, MaxRecvFrag
    response.extend_from_slice(&max_xmit_frag.to_le_bytes());
    response.extend_from_slice(&max_recv_frag.to_le_bytes());
    // AssocGroup
    response.extend_from_slice(&header.call_id.to_le_bytes());
    // SecondaryAddressLength + SecondaryAddress (port "1688\0" + padding)
    if header.packet_type == RPC_PT_BIND_REQ {
        let port_str = b"1688\0";
        response.extend_from_slice(&(port_str.len() as u16).to_le_bytes());
        response.extend_from_slice(port_str);
        // Pad to 4-byte alignment
        let current = response.len();
        let pad = (4 - (current % 4)) % 4;
        response.extend_from_slice(&vec![0u8; pad]);
    } else {
        // Alter context: no secondary address
        response.extend_from_slice(&0u16.to_le_bytes());
        response.extend_from_slice(&[0u8; 2]); // pad
    }

    // NumResults
    response.extend_from_slice(&(num_ctx_items as u32).to_le_bytes());

    // Results for each context item
    for i in 0..num_ctx_items {
        let off = i * CTX_ITEM_SIZE;
        let context_id = u16::from_le_bytes([ctx_items_data[off], ctx_items_data[off + 1]]);
        let interface_uuid = &ctx_items_data[off + 4..off + 20];
        let transfer_syntax = &ctx_items_data[off + 24..off + 40];

        let is_our_interface = interface_uuid == INTERFACE_UUID;

        if is_our_interface && transfer_syntax == TRANSFER_SYNTAX_NDR32 && !has_ndr64 {
            *ndr_ctx = context_id;
            // Accept NDR32
            response.extend_from_slice(&RPC_BIND_ACCEPT.to_le_bytes()); // AckResult
            response.extend_from_slice(&RPC_BIND_ACCEPT.to_le_bytes()); // AckReason
            response.extend_from_slice(&TRANSFER_SYNTAX_NDR32);
            response.extend_from_slice(&2u32.to_le_bytes()); // SyntaxVersion
        } else if is_our_interface && transfer_syntax == TRANSFER_SYNTAX_NDR64 && has_ndr64 {
            *ndr64_ctx = context_id;
            // Accept NDR64
            response.extend_from_slice(&RPC_BIND_ACCEPT.to_le_bytes());
            response.extend_from_slice(&RPC_BIND_ACCEPT.to_le_bytes());
            response.extend_from_slice(&TRANSFER_SYNTAX_NDR64);
            response.extend_from_slice(&1u32.to_le_bytes());
        } else if transfer_syntax.len() >= 8 && transfer_syntax[..8] == BIND_TIME_FEATURE_NEGOTIATION {
            // BTFN
            response.extend_from_slice(&RPC_BIND_ACK.to_le_bytes());
            response.extend_from_slice(&3u16.to_le_bytes()); // SEC_CONTEXT_MULTIPLEX | KEEP_ORPHAN
            response.extend_from_slice(&[0u8; 16]); // TransferSyntax (zeros)
            response.extend_from_slice(&0u32.to_le_bytes());
        } else {
            // Reject
            response.extend_from_slice(&RPC_BIND_NACK.to_le_bytes());
            response.extend_from_slice(&2u16.to_le_bytes()); // SYNTAX_UNSUPPORTED
            response.extend_from_slice(&[0u8; 16]);
            response.extend_from_slice(&0u32.to_le_bytes());
        }
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bind_request_ndr32() -> Vec<u8> {
        let mut payload = Vec::new();
        // MaxXmitFrag
        payload.extend_from_slice(&5840u16.to_le_bytes());
        // MaxRecvFrag
        payload.extend_from_slice(&5840u16.to_le_bytes());
        // AssocGroup
        payload.extend_from_slice(&0u32.to_le_bytes());
        // NumCtxItems = 1
        payload.extend_from_slice(&1u32.to_le_bytes());

        // CtxItem[0]:
        payload.extend_from_slice(&0u16.to_le_bytes()); // ContextId
        payload.extend_from_slice(&1u16.to_le_bytes()); // NumTransItems
        payload.extend_from_slice(&INTERFACE_UUID); // InterfaceUUID
        payload.extend_from_slice(&1u16.to_le_bytes()); // VerMajor
        payload.extend_from_slice(&0u16.to_le_bytes()); // VerMinor
        payload.extend_from_slice(&TRANSFER_SYNTAX_NDR32); // TransferSyntax
        payload.extend_from_slice(&2u32.to_le_bytes()); // SyntaxVersion

        payload
    }

    #[test]
    fn bind_ndr32_accepts() {
        let payload = make_bind_request_ndr32();
        let header = RpcHeader {
            version_major: 5,
            version_minor: 0,
            packet_type: RPC_PT_BIND_REQ,
            packet_flags: RPC_PF_FIRST | RPC_PF_LAST,
            data_representation: 0x10,
            frag_length: (RPC_HEADER_SIZE + payload.len()) as u16,
            auth_length: 0,
            call_id: 1,
        };

        let mut ndr_ctx = RPC_INVALID_CTX;
        let mut ndr64_ctx = RPC_INVALID_CTX;

        let response = handle_bind(&payload, &mut ndr_ctx, &mut ndr64_ctx, &header).unwrap();
        assert_eq!(ndr_ctx, 0);
        assert_eq!(ndr64_ctx, RPC_INVALID_CTX);
        assert!(!response.is_empty());
    }
}
