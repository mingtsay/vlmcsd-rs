use vlmcsd_crypto::{
    AesCtx, AES_KEY_V5, AES_KEY_V6, AES_BLOCK_BYTES,
    aes_decrypt_cbc, aes_encrypt_cbc, sha256, sha256_hmac, xor_block,
};
use vlmcsd_kmsdata::KmsData;
use vlmcsd_types::{Request, VersionInfo, TIME_C1, TIME_C2, TIME_C3};

use crate::{create_response_base, get_16_random_bytes, response_to_wire, DEFAULT_HWID};

pub fn create_response_v6(
    request_data: &[u8],
    kms_data: &KmsData,
) -> Result<Vec<u8>, u32> {
    // Request V6 layout: Version(4) + IV(16) + RequestBase(Request::WIRE_SIZE) + Pad(4)
    let min_size = 4 + 16 + Request::WIRE_SIZE + 4;
    if request_data.len() < min_size {
        return Err(0x8007000D);
    }

    let version = VersionInfo::from_le_bytes(request_data[0..4].try_into().unwrap());
    let v6 = version.major_ver > 5;

    let key = if v6 { AES_KEY_V6.as_slice() } else { AES_KEY_V5.as_slice() };
    let ctx = AesCtx::new(key, v6);

    // Decrypt the request (IV + RequestBase + Pad)
    let mut decrypt_buf = request_data[4..].to_vec();
    let decrypt_size = 16 + Request::WIRE_SIZE + 4;
    if decrypt_buf.len() < decrypt_size {
        return Err(0x8007000D);
    }
    aes_decrypt_cbc(&ctx, None, &mut decrypt_buf[..decrypt_size]);

    let request_iv: [u8; 16] = decrypt_buf[0..16].try_into().unwrap();
    let request = Request::from_le_bytes(&decrypt_buf[16..16 + Request::WIRE_SIZE])
        .ok_or(0x8007000Du32)?;

    let mut hwid = DEFAULT_HWID;
    let response = create_response_base(&request, kms_data, &mut hwid)?;
    let response_wire = response_to_wire(&response);

    // Generate random bytes and hash them
    let random_xored_ivs_raw = get_16_random_bytes();
    let hash = sha256(&random_xored_ivs_raw);

    // XOR random bytes with decrypted request IV
    let mut random_xored_ivs = random_xored_ivs_raw;
    xor_block(&mut random_xored_ivs, &request_iv);

    // Build the response
    let mut result = Vec::new();

    // Version (unencrypted)
    result.extend_from_slice(&version.to_le_bytes());

    // Start of encrypted portion
    let encrypt_start = result.len();

    // Response IV
    let response_iv = if v6 {
        get_16_random_bytes()
    } else {
        request_iv
    };
    result.extend_from_slice(&response_iv);

    // Response base (variable-size wire format)
    result.extend_from_slice(&response_wire);

    // RandomXoredIVs
    result.extend_from_slice(&random_xored_ivs);

    // SHA-256 Hash of random
    result.extend_from_slice(&hash);

    if v6 {
        // HwId
        result.extend_from_slice(&hwid);

        // XoredIVs — in V6 this is just the decrypted request IV
        result.extend_from_slice(&request_iv);

        // HMAC placeholder (16 bytes)
        let hmac_offset = result.len();
        result.extend_from_slice(&[0u8; 16]);

        // Calculate V6 HMAC
        let encrypt_portion = &result[encrypt_start..hmac_offset];
        let hmac = create_v6_hmac(encrypt_portion, &response.client_time.to_le_bytes(), 0);
        result[hmac_offset..hmac_offset + 16].copy_from_slice(&hmac);
    }

    // Encrypt the response (everything after Version)
    let encrypt_ctx = AesCtx::new(key, v6);
    let mut encrypt_data = result[encrypt_start..].to_vec();
    aes_encrypt_cbc(&encrypt_ctx, None, &mut encrypt_data);

    result.truncate(encrypt_start);
    result.extend_from_slice(&encrypt_data);

    Ok(result)
}

pub fn create_request_v6(request: &Request) -> Vec<u8> {
    let v6 = request.version.major_ver > 5;
    let key = if v6 { AES_KEY_V6.as_slice() } else { AES_KEY_V5.as_slice() };

    let iv = get_16_random_bytes();

    let mut result = Vec::new();
    result.extend_from_slice(&request.version.to_le_bytes());
    result.extend_from_slice(&iv);

    let base = request.to_le_bytes();
    let mut encrypt_data = base.to_vec();

    let ctx = AesCtx::new(key, v6);
    aes_encrypt_cbc(&ctx, Some(&iv), &mut encrypt_data);

    result.extend_from_slice(&encrypt_data);
    result
}

pub fn decrypt_response_v6(
    response_data: &[u8],
    _raw_request: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if response_data.len() < 20 {
        return Err("response too short");
    }

    let version = VersionInfo::from_le_bytes(response_data[0..4].try_into().unwrap());
    let v6 = version.major_ver > 5;
    let key = if v6 { AES_KEY_V6.as_slice() } else { AES_KEY_V5.as_slice() };

    let ctx = AesCtx::new(key, v6);
    let mut decrypted = response_data[4..].to_vec();

    if decrypted.len() % AES_BLOCK_BYTES != 0 || decrypted.is_empty() {
        return Err("invalid response size");
    }

    aes_decrypt_cbc(&ctx, None, &mut decrypted);

    // Verify PKCS7 padding
    let last = *decrypted.last().unwrap();
    if last == 0 || last as usize > AES_BLOCK_BYTES {
        return Err("invalid padding");
    }
    let pad_start = decrypted.len() - last as usize;
    if decrypted[pad_start..].iter().any(|&b| b != last) {
        return Err("invalid padding");
    }
    decrypted.truncate(pad_start);

    Ok(decrypted)
}

fn create_v6_hmac(encrypt_data: &[u8], client_time_bytes: &[u8], tolerance: i64) -> [u8; 16] {
    let client_time = u64::from_le_bytes(client_time_bytes[..8].try_into().unwrap_or([0; 8]));
    let time_slot = (client_time / TIME_C1) * TIME_C2 + TIME_C3;
    let time_slot_adjusted = time_slot.wrapping_add((tolerance as u64).wrapping_mul(TIME_C1));

    let time_hash = sha256(&time_slot_adjusted.to_le_bytes());

    // Use last 16 bytes of SHA256 as HMAC key
    let hmac_key = &time_hash[16..32];
    let full_hmac = sha256_hmac(hmac_key, encrypt_data);

    // Return last 16 bytes of HMAC
    let mut result = [0u8; 16];
    result.copy_from_slice(&full_hmac[16..32]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlmcsd_types::{FileTime, Guid};

    fn make_test_request(major_ver: u16) -> Request {
        Request {
            version: VersionInfo { major_ver, minor_ver: 0 },
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
        }
    }

    #[test]
    fn create_v5_request_encrypts() {
        let request = make_test_request(5);
        let data = create_request_v6(&request);
        // Version(4) + IV(16) + encrypted(padded request)
        assert!(data.len() >= 4 + 16 + Request::WIRE_SIZE);
    }

    #[test]
    fn create_v6_request_encrypts() {
        let request = make_test_request(6);
        let data = create_request_v6(&request);
        assert!(data.len() >= 4 + 16 + Request::WIRE_SIZE);
    }

    #[test]
    fn create_v6_response_succeeds() {
        let kms = KmsData::load_embedded();
        let request = make_test_request(6);
        let request_data = create_request_v6(&request);

        let response = create_response_v6(&request_data, &kms);
        assert!(response.is_ok());
        let resp_data = response.unwrap();
        assert!(resp_data.len() > 20);
    }

    #[test]
    fn create_v5_response_succeeds() {
        let kms = KmsData::load_embedded();
        let request = make_test_request(5);
        let request_data = create_request_v6(&request);

        let response = create_response_v6(&request_data, &kms);
        assert!(response.is_ok());
    }

    #[test]
    fn v6_hmac_deterministic() {
        let data = [0u8; 64];
        let time = 1700000000u64.to_le_bytes();
        let hmac1 = create_v6_hmac(&data, &time, 0);
        let hmac2 = create_v6_hmac(&data, &time, 0);
        assert_eq!(hmac1, hmac2);
    }

    #[test]
    fn v6_hmac_tolerance_differs() {
        let data = [0u8; 64];
        let time = 1700000000u64.to_le_bytes();
        let hmac0 = create_v6_hmac(&data, &time, 0);
        let hmac1 = create_v6_hmac(&data, &time, 1);
        assert_ne!(hmac0, hmac1);
    }
}
