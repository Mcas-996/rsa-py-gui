// RSA Encryption Implementation
// Implements RSA encryption with PKCS#1 v1.5 padding

use super::bigint::{RsaBigInt, from_bytes, to_bytes, mod_pow};
use super::keygen::RsaPublicKey;
use super::padding::{pad_pkcs1_v15, PaddedData};

/// Encrypt bytes using RSA public key
/// Returns ciphertext as bytes
pub fn encrypt_bytes(plaintext: &[u8], public_key: &RsaPublicKey) -> Result<Vec<u8>, String> {
    // Apply PKCS#1 v1.5 padding
    let padded = pad_pkcs1_v15(plaintext, public_key)?;

    // Convert to big integer
    let m = from_bytes(&padded.data);

    // Compute c = m^e mod n
    let c = mod_pow(&m, &public_key.e, &public_key.n);

    // Convert to bytes
    let ciphertext = to_bytes(&c);

    // Pad with leading zeros to match key size
    let key_bytes: usize = ((public_key.bit_length() + 7) / 8) as usize;
    let mut result = vec![0u8; key_bytes];
    let start = key_bytes.saturating_sub(ciphertext.len());
    result[start..].copy_from_slice(&ciphertext);

    Ok(result)
}

/// Encrypt a string using RSA public key
pub fn encrypt_string(plaintext: &str, public_key: &RsaPublicKey) -> Result<Vec<u8>, String> {
    encrypt_bytes(plaintext.as_bytes(), public_key)
}

/// Encrypt a u64 value using RSA public key
pub fn encrypt_u64(value: u64, public_key: &RsaPublicKey) -> Result<Vec<u8>, String> {
    let bytes = value.to_le_bytes();
    encrypt_bytes(&bytes, public_key)
}

/// Encrypt data with OAEP padding (placeholder for future implementation)
pub fn encrypt_oaep(plaintext: &[u8], public_key: &RsaPublicKey, _label: &[u8]) -> Result<Vec<u8>, String> {
    // TODO: Implement OAEP padding
    // For now, fall back to PKCS#1 v1.5
    encrypt_bytes(plaintext, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::keygen::generate_keypair;

    #[test]
    fn test_encrypt_bytes() {
        let keypair = generate_keypair(512, 65537).unwrap();
        let message = b"Hello, RSA!";

        let ciphertext = encrypt_bytes(message, &keypair.public_key).unwrap();
        assert!(ciphertext.len() >= 64); // 512 bits = 64 bytes

        // Verify it's not the same as plaintext
        assert_ne!(ciphertext, message);
    }

    #[test]
    fn test_encrypt_string() {
        let keypair = generate_keypair(512, 65537).unwrap();
        let message = "Test message";

        let ciphertext = encrypt_string(message, &keypair.public_key).unwrap();
        assert!(ciphertext.len() >= 64);
    }

    #[test]
    fn test_encrypt_u64() {
        let keypair = generate_keypair(512, 65537).unwrap();
        let value: u64 = 1234567890;

        let ciphertext = encrypt_u64(value, &keypair.public_key).unwrap();
        assert!(ciphertext.len() >= 64);
    }

    #[test]
    fn test_encrypt_large_data() {
        let keypair = generate_keypair(2048, 65537).unwrap();
        // Create message that's almost the key size
        let message = vec![0u8; 200];

        let ciphertext = encrypt_bytes(&message, &keypair.public_key).unwrap();
        assert_eq!(ciphertext.len(), 256); // 2048 bits = 256 bytes
    }

    #[test]
    fn test_encrypt_empty() {
        let keypair = generate_keypair(512, 65537).unwrap();
        let message = b"";

        let result = encrypt_bytes(message, &keypair.public_key);
        assert!(result.is_err()); // Empty message should fail padding
    }
}
