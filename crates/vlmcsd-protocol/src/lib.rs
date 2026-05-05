mod epid;
mod v4;
mod v6;

pub use epid::generate_random_epid;
pub use v4::{create_request_v4, create_response_v4};
pub use v6::{create_request_v6, create_response_v6, decrypt_response_v6};

use vlmcsd_types::{Request, Response};
use vlmcsd_kmsdata::KmsData;

pub const VL_ACTIVATION_INTERVAL: u32 = 120;
pub const VL_RENEWAL_INTERVAL: u32 = 10080;

pub const DEFAULT_HWID: [u8; 8] = [0x36, 0x4F, 0x46, 0x3A, 0x88, 0x63, 0xD3, 0x5F];

pub fn create_response_base(
    request: &Request,
    kms_data: &KmsData,
    hwid: &mut [u8; 8],
) -> Result<Response, u32> {
    let n_policy = request.n_policy;
    let required_clients = if n_policy < 1 { 1 } else { n_policy * 2 };

    let kms_item = kms_data.find_kms_item(&request.kms_id);
    let epid_index = kms_item.map(|i| i.epid_index as usize).unwrap_or(0);

    let min_active = kms_data.csvlk_data.get(epid_index)
        .map(|c| c.min_active_clients as u32)
        .unwrap_or(25);

    let count = if required_clients > min_active {
        required_clients
    } else {
        min_active
    };

    let epid_str = kms_data.get_epid(epid_index);
    let mut kms_pid = [0u16; 64];
    let pid_chars: Vec<u16> = epid_str.encode_utf16().chain(std::iter::once(0)).collect();
    let copy_len = pid_chars.len().min(64);
    kms_pid[..copy_len].copy_from_slice(&pid_chars[..copy_len]);
    let pid_size = (copy_len as u32) * 2;

    *hwid = DEFAULT_HWID;

    Ok(Response {
        version: request.version,
        pid_size,
        kms_pid,
        cmid: request.cmid,
        client_time: request.client_time,
        count,
        vl_activation_interval: VL_ACTIVATION_INTERVAL,
        vl_renewal_interval: VL_RENEWAL_INTERVAL,
    })
}

pub fn response_to_wire(response: &Response) -> Vec<u8> {
    let pid_size = response.pid_size as usize;
    let pre_epid = 4 + 4; // version + pid_size
    let post_epid = 16 + 8 + 4 + 4 + 4; // CMID + ClientTime + Count + VLActivation + VLRenewal

    let total = pre_epid + pid_size + post_epid;
    let mut buf = Vec::with_capacity(total);

    buf.extend_from_slice(&response.version.to_le_bytes());
    buf.extend_from_slice(&response.pid_size.to_le_bytes());

    let pid_u16_count = pid_size / 2;
    for i in 0..pid_u16_count {
        if i < 64 {
            buf.extend_from_slice(&response.kms_pid[i].to_le_bytes());
        } else {
            buf.extend_from_slice(&0u16.to_le_bytes());
        }
    }

    buf.extend_from_slice(&response.cmid.to_le_bytes());
    buf.extend_from_slice(&response.client_time.to_le_bytes());
    buf.extend_from_slice(&response.count.to_le_bytes());
    buf.extend_from_slice(&response.vl_activation_interval.to_le_bytes());
    buf.extend_from_slice(&response.vl_renewal_interval.to_le_bytes());

    buf
}

pub fn get_random_bytes(buf: &mut [u8]) {
    // Simple PRNG seeded from system for non-crypto randomness
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let mut state = seed ^ 0x6a09e667bb67ae85;
    for byte in buf.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
}

pub fn get_16_random_bytes() -> [u8; 16] {
    let mut buf = [0u8; 16];
    get_random_bytes(&mut buf);
    buf
}
