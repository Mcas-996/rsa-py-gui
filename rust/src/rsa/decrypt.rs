// RSA Decryption Implementation
// Implements RSA decryption with Chinese Remainder Theorem (CRT) optimization

use super::bigint::{RsaBigInt, from_bytes, mod_pow};
use super::keygen::RsaPrivateKey;
use super::padding::{unpad_pkcs1_v15, PaddedData};

/// Decrypt ciphertext bytes using RSA private key
/// Returns plaintext as bytes
pub fn decrypt_bytes(ciphertext: &[u8], private_key: &RsaPrivateKey) -> Result<Vec<u8>, String> {
    // Convert ciphertext to big integer
    let c = from_bytes(ciphertext);

    // Validate ciphertext size
    let key_bytes: usize = ((private_key.bit_length() + 7) / 8) as usize;
    if ciphertext.len() != key_bytes {
        return Err(format!(
            "Invalid ciphertext length: expected {} bytes, got {}",
            key_bytes,
            ciphertext.len()
        ));
    }

    // Use CRT-based decryption for better performance
    let m = decrypt_crt(&c, private_key);

    // Convert to bytes
    let m_bytes = m.to_bytes_be();

    // Remove leading zeros
    let padded = PaddedData {
        data: m_bytes,
        expected_size: key_bytes,
    };

    // Remove PKCS#1 v1.5 padding
    let plaintext = unpad_pkcs1_v15(padded)?;

    Ok(plaintext)
}

/// Decrypt using Chinese Remainder Theorem (CRT)
/// This is faster than regular decryption because we work with smaller numbers
fn decrypt_crt(c: &RsaBigInt, key: &RsaPrivateKey) -> RsaBigInt {
    // m1 = c^d_p mod p
    let m1 = mod_pow(c, &key.d_p, &key.p);

    // m2 = c^d_q mod q
    let m2 = mod_pow(c, &key.d_q, &key.q);

    // h = (m1 - m2) * q_inv mod p
    let m1_cloned = m1.clone();
    let m2_cloned = m2.clone();
    let mut h = if m1_cloned >= m2_cloned {
        m1_cloned - m2_cloned
    } else {
        m1_cloned + &key.p - m2_cloned
    };
    h = (h * &key.q_inv) % &key.p;

    // m = m2 + q * h
    let m = m2 + &key.q * h;

    // Ensure m < n
    let n = &key.n;
    if m >= *n {
        return m - n;
    }

    m
}

/// Decrypt ciphertext to a string
pub fn decrypt_to_string(ciphertext: &[u8], private_key: &RsaPrivateKey) -> Result<String, String> {
    let plaintext = decrypt_bytes(ciphertext, private_key)?;
    String::from_utf8(plaintext).map_err(|e| format!("Invalid UTF-8: {}", e))
}

/// Decrypt ciphertext to u64
pub fn decrypt_to_u64(ciphertext: &[u8], private_key: &RsaPrivateKey) -> Result<u64, String> {
    let plaintext = decrypt_bytes(ciphertext, private_key)?;
    if plaintext.len() != 8 {
        return Err(format!("Expected 8 bytes for u64, got {}", plaintext.len()));
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&plaintext);
    Ok(u64::from_le_bytes(bytes))
}

/// Decrypt data with OAEP padding (placeholder for future implementation)
pub fn decrypt_oaep(ciphertext: &[u8], private_key: &RsaPrivateKey, _label: &[u8]) -> Result<Vec<u8>, String> {
    // TODO: Implement OAEP unpadding
    // For now, fall back to PKCS#1 v1.5
    decrypt_bytes(ciphertext, private_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::keygen::{generate_keypair, RsaKeyPair};

    fn test_roundtrip(keypair: &RsaKeyPair, message: &[u8]) {
        let ciphertext = keypair.public_key.encrypt(message).unwrap();
        let decrypted = keypair.private_key.decrypt(&ciphertext).unwrap();
        assert_eq!(message, decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_bytes() {
        let keypair = generate_keypair(512, 65537).unwrap();
        let message = b"Hello, RSA!";

        let ciphertext = keypair.public_key.encrypt(message).unwrap();
        let decrypted = decrypt_bytes(&ciphertext, &keypair.private_key).unwrap();

        assert_eq!(message.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_string() {
        let keypair = generate_keypair(512, 65537).unwrap();
        let message = "Test message for RSA decryption";

        let ciphertext = keypair.public_key.encrypt(message.as_bytes()).unwrap();
        let decrypted = decrypt_to_string(&ciphertext, &keypair.private_key).unwrap();

        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_decrypt_u64() {
        let keypair = generate_keypair(512, 65537).unwrap();
        let value: u64 = 1234567890123456789;

        let ciphertext = keypair.public_key.encrypt(&value.to_le_bytes()).unwrap();
        let decrypted = decrypt_to_u64(&ciphertext, &keypair.private_key).unwrap();

        assert_eq!(value, decrypted);
    }

    #[test]
    fn test_decrypt_invalid_size() {
        let keypair = generate_keypair(512, 65537).unwrap();
        let result = decrypt_bytes(&[0u8; 10], &keypair.private_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let keypair1 = generate_keypair(512, 65537).unwrap();
        let keypair2 = generate_keypair(512, 65537).unwrap();

        let message = b"Test";
        let ciphertext = keypair1.public_key.encrypt(message).unwrap();

        let result = keypair2.private_key.decrypt(&ciphertext);
        assert!(result.is_err()); // Should fail - wrong key
    }

    #[test]
    fn test_roundtrip_various_sizes() {
        let keypair = generate_keypair(2048, 65537).unwrap();

        // Test various message sizes
        let test_cases = vec![
            b"A",
            b"AB",
            b"Hello",
            b"Hello, World!",
            vec![0u8; 100],
            vec![255u8; 100],
        ];

        for message in test_cases {
            test_roundtrip(&keypair, &message);
        }
    }
}