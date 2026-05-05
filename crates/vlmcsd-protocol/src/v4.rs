use vlmcsd_crypto::aes_cmac_v4;
use vlmcsd_kmsdata::KmsData;
use vlmcsd_types::Request;

use crate::{create_response_base, response_to_wire};

pub fn create_response_v4(
    request_data: &[u8],
    kms_data: &KmsData,
) -> Result<Vec<u8>, u32> {
    if request_data.len() < Request::WIRE_SIZE + 16 {
        return Err(0x8007000D);
    }

    let request = Request::from_le_bytes(request_data).ok_or(0x8007000Du32)?;

    let mut hwid = [0u8; 8];
    let response = create_response_base(&request, kms_data, &mut hwid)?;

    let response_wire = response_to_wire(&response);
    let mac = aes_cmac_v4(&response_wire);

    let mut result = response_wire;
    result.extend_from_slice(&mac);
    Ok(result)
}

pub fn create_request_v4(request: &Request) -> Vec<u8> {
    let base = request.to_le_bytes();
    let mac = aes_cmac_v4(&base);

    let mut result = Vec::with_capacity(base.len() + 16);
    result.extend_from_slice(&base);
    result.extend_from_slice(&mac);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlmcsd_types::{FileTime, Guid, VersionInfo};

    #[test]
    fn create_v4_request_has_correct_size() {
        let request = Request {
            version: VersionInfo { major_ver: 4, minor_ver: 0 },
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
            workstation_name: [0u16; 64],
        };
        let data = create_request_v4(&request);
        assert_eq!(data.len(), Request::WIRE_SIZE + 16);
    }

    #[test]
    fn create_v4_response_succeeds() {
        let kms = KmsData::load_embedded();
        let request = Request {
            version: VersionInfo { major_ver: 4, minor_ver: 0 },
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
            workstation_name: [0u16; 64],
        };
        let request_data = create_request_v4(&request);
        let response = create_response_v4(&request_data, &kms);
        assert!(response.is_ok());
        let resp_data = response.unwrap();
        // Response should have version(4) + pid_size(4) + pid + CMID(16) + time(8) + count(4) + intervals(8) + MAC(16)
        assert!(resp_data.len() > 16);
    }
}
