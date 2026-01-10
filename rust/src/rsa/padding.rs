// PKCS#1 v1.5 Padding
// Implements RSA PKCS#1 v1.5 padding for encryption and signatures

use std::fmt;

/// Padded data structure
#[derive(Debug, Clone)]
pub struct PaddedData {
    pub data: Vec<u8>,
    pub expected_size: usize,
}

/// PKCS#1 v1.5 Padding for encryption
/// Format: 0x00 || 0x02 || PS || 0x00 || data
/// PS = padding string of non-zero random bytes (at least 8 bytes)
pub fn pad_pkcs1_v15(data: &[u8], _public_key: &super::keygen::RsaPublicKey) -> Result<PaddedData, String> {
    // Calculate key size in bytes
    let key_size: usize = ((_public_key.bit_length() + 7) / 8) as usize;

    // Minimum padding: 0x00 0x02 (2 bytes) + at least 8 non-zero bytes + 0x00 (1 byte)
    // So minimum data size is 11 bytes
    let min_data_size = 11usize;

    if data.len() > key_size - min_data_size {
        return Err(format!(
            "Data too large: max {} bytes, got {}",
            key_size - min_data_size,
            data.len()
        ));
    }

    // Generate padding string (PS) with random non-zero bytes
    // Minimum 8 bytes of padding
    let ps_len = key_size - data.len() - 3; // 2 (00 02) + 1 (00) + data
    let min_ps_len = 8usize;

    let ps_len = if ps_len < min_ps_len { min_ps_len } else { ps_len };

    let mut padding = vec![0u8; ps_len];
    for byte in &mut padding {
        *byte = rand::random::<u8>();
        // Ensure non-zero bytes (0x01 to 0xFF)
        if *byte == 0 {
            *byte = 1;
        }
    }

    // Build padded message: 0x00 || 0x02 || PS || 0x00 || data
    let mut result = Vec::with_capacity(key_size);
    result.push(0x00);
    result.push(0x02);
    result.extend_from_slice(&padding);
    result.push(0x00);
    result.extend_from_slice(data);

    // Pad with leading zeros if needed
    if result.len() < key_size {
        let zeros_needed = key_size - result.len();
        let mut padded = vec![0u8; zeros_needed];
        padded.extend_from_slice(&result);
        result = padded;
    }

    Ok(PaddedData {
        data: result,
        expected_size: key_size,
    })
}

/// Remove PKCS#1 v1.5 padding from encrypted data
/// Validates the padding structure and extracts the original data
pub fn unpad_pkcs1_v15(padded: PaddedData) -> Result<Vec<u8>, String> {
    let data = padded.data;

    // Validate minimum length
    if data.len() < 11 {
        return Err("Invalid padding: data too short".to_string());
    }

    // Check leading bytes
    if data[0] != 0x00 {
        return Err("Invalid padding: first byte must be 0x00".to_string());
    }

    if data[1] != 0x02 {
        return Err("Invalid padding: second byte must be 0x02".to_string());
    }

    // Find the separator byte (0x00)
    let separator_pos = match data[2..].iter().position(|&b| b == 0x00) {
        Some(pos) => pos + 2, // +2 because we started from index 2
        None => {
            return Err("Invalid padding: no separator byte found".to_string());
        }
    };

    // The separator must be at least at position 10 (after 0x00 0x02 + 8 bytes minimum)
    if separator_pos < 10 {
        return Err("Invalid padding: padding too short".to_string());
    }

    // Extract the original data (after the separator)
    let original_data = &data[separator_pos + 1..];

    if original_data.is_empty() {
        return Err("Invalid padding: no data after separator".to_string());
    }

    Ok(original_data.to_vec())
}

/// PKCS#1 v1.5 Signature padding (EMSA-PKCS1-v1_5)
/// Format: 0x00 || 0x01 || PS (0xFF) || 0x00 || DER(OID) || digest
pub fn pad_for_signature(data: &[u8], _algorithm_oid: &[u8]) -> Result<Vec<u8>, String> {
    // This is a simplified version for demonstration
    // Full implementation would include proper DER-encoded OID

    let digest_size = data.len();
    let total_size = 11 + 10 + digest_size; // Basic overhead + SHA-256 OID placeholder + digest

    let mut result = Vec::with_capacity(total_size);
    result.push(0x00);
    result.push(0x01);

    // PS = 0xFF bytes
    let ps_size = total_size - 2 - 1 - 10 - digest_size; // 00 01 + 00 + OID + digest
    result.extend(vec![0xFF; ps_size]);

    result.push(0x00);

    // OID placeholder for SHA-256
    result.extend_from_slice(&[0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);

    result.extend_from_slice(data);

    Ok(result)
}

/// Remove signature padding (simplified)
pub fn unpad_for_signature(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 11 {
        return Err("Invalid signature padding: too short".to_string());
    }

    if data[0] != 0x00 || data[1] != 0x01 {
        return Err("Invalid signature padding: wrong magic bytes".to_string());
    }

    // Find the end of PS (0xFF bytes)
    let mut pos = 2;
    while pos < data.len() && data[pos] == 0xFF {
        pos += 1;
    }

    // Check for separator
    if pos >= data.len() || data[pos] != 0x00 {
        return Err("Invalid signature padding: no separator".to_string());
    }

    Ok(data[pos + 1..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::keygen::{generate_keypair, RsaPublicKey};
    use rand::Rng;

    fn get_test_public_key() -> RsaPublicKey {
        generate_keypair(512, 65537).unwrap().public_key
    }

    #[test]
    fn test_pad_pkcs1_v15() {
        let key = get_test_public_key();
        let data = b"Hello";

        let padded = pad_pkcs1_v15(data, &key).unwrap();
        assert_eq!(padded.data.len(), 64); // 512 bits = 64 bytes

        // Check structure
        assert_eq!(padded.data[0], 0x00);
        assert_eq!(padded.data[1], 0x02);
        assert_eq!(padded.data[padded.data.len() - data.len() - 1], 0x00);

        // Check that padding bytes are non-zero
        for &byte in &padded.data[2..padded.data.len() - data.len() - 1] {
            assert_ne!(byte, 0x00);
        }
    }

    #[test]
    fn test_pad_max_size() {
        let key = get_test_public_key();
        // Maximum data size for 512-bit key: 64 - 11 = 53 bytes
        let data = vec![0u8; 53];

        let padded = pad_pkcs1_v15(&data, &key).unwrap();
        assert_eq!(padded.data.len(), 64);
    }

    #[test]
    fn test_pad_too_large() {
        let key = get_test_public_key();
        // 54 bytes is too large for 512-bit key
        let data = vec![0u8; 54];

        let result = pad_pkcs1_v15(&data, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_unpad_pkcs1_v15() {
        let key = get_test_public_key();
        let original = b"Test data";

        let padded = pad_pkcs1_v15(original, &key).unwrap();
        let unpadded = unpad_pkcs1_v15(padded).unwrap();

        assert_eq!(original.as_slice(), unpadded.as_slice());
    }

    #[test]
    fn test_roundtrip() {
        let key = get_test_public_key();
        let test_data = vec![
            b"A",
            b"AB",
            b"Hello",
            b"Hello, World!",
            b"Longer test data with more content",
        ];

        for data in test_data {
            let padded = pad_pkcs1_v15(data, &key).unwrap();
            let unpadded = unpad_pkcs1_v15(padded).unwrap();
            assert_eq!(data.as_slice(), unpadded.as_slice());
        }
    }

    #[test]
    fn test_invalid_padding() {
        let data = PaddedData {
            data: vec![0x00, 0x03, 0x00, 0x01, 0x02, 0x03], // Wrong 2nd byte
            expected_size: 6,
        };

        let result = unpad_pkcs1_v15(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_separator() {
        let data = PaddedData {
            data: vec![0x00, 0x02, 0xFF, 0xFF, 0x01, 0x02, 0x03], // No separator
            expected_size: 7,
        };

        let result = unpad_pkcs1_v15(data);
        assert!(result.is_err());
    }
}
