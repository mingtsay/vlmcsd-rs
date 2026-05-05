use crate::{FileTime, Guid};

pub const PID_BUFFER_SIZE: usize = 64;
pub const WORKSTATION_NAME_BUFFER: usize = 64;
pub const MAX_RESPONSE_SIZE: usize = 384;
pub const MAX_CLIENTS: usize = 671;

pub const TIME_C1: u64 = 0x00000022816889BD;
pub const TIME_C2: u64 = 0x000000208CBAB5ED;
pub const TIME_C3: u64 = 0x3156CD5AC628477A;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct VersionInfo {
    pub minor_ver: u16,
    pub major_ver: u16,
}

impl VersionInfo {
    pub fn version_u32(self) -> u32 {
        (self.major_ver as u32) << 16 | self.minor_ver as u32
    }

    pub fn from_le_bytes(bytes: &[u8; 4]) -> Self {
        VersionInfo {
            minor_ver: u16::from_le_bytes([bytes[0], bytes[1]]),
            major_ver: u16::from_le_bytes([bytes[2], bytes[3]]),
        }
    }

    pub fn to_le_bytes(self) -> [u8; 4] {
        let mut out = [0u8; 4];
        out[0..2].copy_from_slice(&self.minor_ver.to_le_bytes());
        out[2..4].copy_from_slice(&self.major_ver.to_le_bytes());
        out
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub version: VersionInfo,
    pub vm_info: u32,
    pub license_status: u32,
    pub binding_expiration: u32,
    pub app_id: Guid,
    pub act_id: Guid,
    pub kms_id: Guid,
    pub cmid: Guid,
    pub n_policy: u32,
    pub client_time: FileTime,
    pub cmid_prev: Guid,
    pub workstation_name: [u16; WORKSTATION_NAME_BUFFER],
}

impl Request {
    pub const WIRE_SIZE: usize = 4 + 4 + 4 + 4 + 16 + 16 + 16 + 16 + 4 + 8 + 16 + 128;

    pub fn from_le_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::WIRE_SIZE {
            return None;
        }
        let mut off = 0;

        let version = VersionInfo::from_le_bytes(data[off..off + 4].try_into().unwrap());
        off += 4;
        let vm_info = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        off += 4;
        let license_status = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        off += 4;
        let binding_expiration = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        off += 4;
        let app_id = Guid::from_le_bytes(data[off..off + 16].try_into().unwrap());
        off += 16;
        let act_id = Guid::from_le_bytes(data[off..off + 16].try_into().unwrap());
        off += 16;
        let kms_id = Guid::from_le_bytes(data[off..off + 16].try_into().unwrap());
        off += 16;
        let cmid = Guid::from_le_bytes(data[off..off + 16].try_into().unwrap());
        off += 16;
        let n_policy = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        off += 4;
        let client_time = FileTime::from_le_bytes(data[off..off + 8].try_into().unwrap());
        off += 8;
        let cmid_prev = Guid::from_le_bytes(data[off..off + 16].try_into().unwrap());
        off += 16;

        let mut workstation_name = [0u16; WORKSTATION_NAME_BUFFER];
        for i in 0..WORKSTATION_NAME_BUFFER {
            workstation_name[i] =
                u16::from_le_bytes(data[off..off + 2].try_into().unwrap());
            off += 2;
        }

        Some(Request {
            version,
            vm_info,
            license_status,
            binding_expiration,
            app_id,
            act_id,
            kms_id,
            cmid,
            n_policy,
            client_time,
            cmid_prev,
            workstation_name,
        })
    }

    pub fn to_le_bytes(&self) -> [u8; Self::WIRE_SIZE] {
        let mut out = [0u8; Self::WIRE_SIZE];
        let mut off = 0;

        out[off..off + 4].copy_from_slice(&self.version.to_le_bytes());
        off += 4;
        out[off..off + 4].copy_from_slice(&self.vm_info.to_le_bytes());
        off += 4;
        out[off..off + 4].copy_from_slice(&self.license_status.to_le_bytes());
        off += 4;
        out[off..off + 4].copy_from_slice(&self.binding_expiration.to_le_bytes());
        off += 4;
        out[off..off + 16].copy_from_slice(&self.app_id.to_le_bytes());
        off += 16;
        out[off..off + 16].copy_from_slice(&self.act_id.to_le_bytes());
        off += 16;
        out[off..off + 16].copy_from_slice(&self.kms_id.to_le_bytes());
        off += 16;
        out[off..off + 16].copy_from_slice(&self.cmid.to_le_bytes());
        off += 16;
        out[off..off + 4].copy_from_slice(&self.n_policy.to_le_bytes());
        off += 4;
        out[off..off + 8].copy_from_slice(&self.client_time.to_le_bytes());
        off += 8;
        out[off..off + 16].copy_from_slice(&self.cmid_prev.to_le_bytes());
        off += 16;

        for i in 0..WORKSTATION_NAME_BUFFER {
            out[off..off + 2].copy_from_slice(&self.workstation_name[i].to_le_bytes());
            off += 2;
        }

        out
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    pub version: VersionInfo,
    pub pid_size: u32,
    pub kms_pid: [u16; PID_BUFFER_SIZE],
    pub cmid: Guid,
    pub client_time: FileTime,
    pub count: u32,
    pub vl_activation_interval: u32,
    pub vl_renewal_interval: u32,
}

pub type HwId = [u8; 8];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let req = Request {
            version: VersionInfo {
                major_ver: 6,
                minor_ver: 0,
            },
            vm_info: 0,
            license_status: 1,
            binding_expiration: 43200,
            app_id: Guid::ZERO,
            act_id: Guid::ZERO,
            kms_id: Guid::ZERO,
            cmid: Guid::ZERO,
            n_policy: 25,
            client_time: FileTime::from_unix_secs(1700000000),
            cmid_prev: Guid::ZERO,
            workstation_name: [0u16; WORKSTATION_NAME_BUFFER],
        };
        let bytes = req.to_le_bytes();
        let req2 = Request::from_le_bytes(&bytes).unwrap();
        assert_eq!(req2.version.major_ver, 6);
        assert_eq!(req2.n_policy, 25);
        assert_eq!(req2.to_le_bytes(), bytes);
    }
}
