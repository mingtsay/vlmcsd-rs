use std::io::{self, Read};

pub const RPC_HEADER_SIZE: usize = 16;

pub const RPC_PT_REQUEST: u8 = 0;
pub const RPC_PT_RESPONSE: u8 = 2;
pub const RPC_PT_FAULT: u8 = 3;
pub const RPC_PT_BIND_REQ: u8 = 11;
pub const RPC_PT_BIND_ACK: u8 = 12;
pub const RPC_PT_ALTERCONTEXT_REQ: u8 = 14;
pub const RPC_PT_ALTERCONTEXT_ACK: u8 = 15;

pub const RPC_PF_FIRST: u8 = 1;
pub const RPC_PF_LAST: u8 = 2;

pub const RPC_INVALID_CTX: u16 = 0xFFFF;

#[derive(Debug, Clone)]
pub struct RpcHeader {
    pub version_major: u8,
    pub version_minor: u8,
    pub packet_type: u8,
    pub packet_flags: u8,
    pub data_representation: u32,
    pub frag_length: u16,
    pub auth_length: u16,
    pub call_id: u32,
}

impl RpcHeader {
    pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; RPC_HEADER_SIZE];
        reader.read_exact(&mut buf)?;

        Ok(RpcHeader {
            version_major: buf[0],
            version_minor: buf[1],
            packet_type: buf[2],
            packet_flags: buf[3],
            data_representation: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            frag_length: u16::from_le_bytes([buf[8], buf[9]]),
            auth_length: u16::from_le_bytes([buf[10], buf[11]]),
            call_id: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
        })
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.push(self.version_major);
        buf.push(self.version_minor);
        buf.push(self.packet_type);
        buf.push(self.packet_flags);
        buf.extend_from_slice(&self.data_representation.to_le_bytes());
        buf.extend_from_slice(&self.frag_length.to_le_bytes());
        buf.extend_from_slice(&self.auth_length.to_le_bytes());
        buf.extend_from_slice(&self.call_id.to_le_bytes());
    }
}
