// RSA Key Generation
// Implements RSA key pair generation (public and private keys)

use super::bigint::{
    RsaBigInt, from_u64, mod_inverse, is_probable_prime, random_prime,
    gcd, lcm,
};

/// RSA Public Key
#[derive(Debug, Clone, PartialEq)]
pub struct RsaPublicKey {
    pub n: RsaBigInt,  // Modulus
    pub e: RsaBigInt,  // Public exponent
}

/// RSA Private Key
#[derive(Debug, Clone, PartialEq)]
pub struct RsaPrivateKey {
    pub n: RsaBigInt,      // Modulus (same as public)
    pub d: RsaBigInt,      // Private exponent
    pub p: RsaBigInt,      // First prime factor
    pub q: RsaBigInt,      // Second prime factor
    // Pre-computed values for faster decryption
    pub d_p: RsaBigInt,    // d mod (p-1)
    pub d_q: RsaBigInt,    // d mod (q-1)
    pub q_inv: RsaBigInt,  // q^(-1) mod p
}

/// RSA Key Pair (both public and private keys)
#[derive(Debug, Clone)]
pub struct RsaKeyPair {
    pub public_key: RsaPublicKey,
    pub private_key: RsaPrivateKey,
    pub bit_length: u32,
}

impl RsaPublicKey {
    /// Get the bit length of the modulus
    pub fn bit_length(&self) -> u32 {
        let n_bytes = self.n.to_bytes_be();
        (n_bytes.len() * 8) as u32
    }

    /// Encrypt a message using this public key
    /// Returns ciphertext as bytes
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        use super::encrypt::encrypt_bytes;
        encrypt_bytes(plaintext, self)
    }
}

impl RsaPrivateKey {
    /// Get the bit length of the modulus
    pub fn bit_length(&self) -> u32 {
        let n_bytes = self.n.to_bytes_be();
        (n_bytes.len() * 8) as u32
    }

    /// Decrypt a ciphertext using this private key
    /// Returns plaintext as bytes
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        use super::decrypt::decrypt_bytes;
        decrypt_bytes(ciphertext, self)
    }
}

impl RsaKeyPair {
    /// Get the bit length of the key
    pub fn bit_length(&self) -> u32 {
        self.public_key.bit_length()
    }
}

/// Generate RSA key pair with specified bit length
/// bit_length: Size of the modulus in bits (2048, 3072, 4096, etc.)
/// e: Public exponent (common values: 3, 17, 65537)
///
/// Returns RsaKeyPair on success
pub fn generate_keypair(bit_length: u32, e: u64) -> Result<RsaKeyPair, String> {
    if bit_length < 512 {
        return Err("Bit length must be at least 512".to_string());
    }
    if bit_length % 2 != 0 {
        return Err("Bit length must be even (p and q should have equal bit length)".to_string());
    }

    let e = from_u64(e);
    let half_bits = bit_length / 2;

    // Step 1: Generate two random primes p and q
    let p = random_prime(half_bits);
    let q = random_prime(half_bits);

    // Ensure p != q
    if p == q {
        // Convert e back to u64 for recursive call
        let e_u64: u64 = e.try_into().unwrap_or(65537);
        return generate_keypair(bit_length, e_u64);
    }

    // Ensure p > q (for q_inv calculation)
    let (p, q) = if p < q {
        (q, p)
    } else {
        (p, q)
    };

    // Step 2: Compute n = p * q
    let n = &p * &q;

    // Step 3: Compute φ(n) = (p-1)(q-1)
    let phi_n = (&p - 1u8) * (&q - 1u8);

    // Step 4: Verify e and φ(n) are coprime
    if gcd(&e, &phi_n) != from_u64(1) {
        return Err(format!("e={} is not coprime with φ(n)", e));
    }

    // Step 5: Compute d = e^(-1) mod φ(n)
    let d = match mod_inverse(&e, &phi_n) {
        Some(d) => d,
        None => {
            return Err("Failed to compute modular inverse".to_string());
        }
    };

    // Step 6: Compute CRT parameters for faster decryption
    let p_minus_1 = &p - 1u8;
    let q_minus_1 = &q - 1u8;
    let d_p = &d % &p_minus_1;
    let d_q = &d % &q_minus_1;
    let q_inv = match mod_inverse(&q, &p) {
        Some(inv) => inv,
        None => {
            return Err("Failed to compute q^(-1) mod p".to_string());
        }
    };

    // Create keys
    let public_key = RsaPublicKey {
        n: n.clone(),
        e: e.clone(),
    };

    let private_key = RsaPrivateKey {
        n: n.clone(),
        d: d.clone(),
        p,
        q,
        d_p,
        d_q,
        q_inv,
    };

    Ok(RsaKeyPair {
        public_key,
        private_key,
        bit_length,
    })
}

/// Generate RSA key pair with default settings (2048 bits, e=65537)
pub fn generate_default_keypair() -> Result<RsaKeyPair, String> {
    generate_keypair(2048, 65537)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = generate_keypair(512, 65537);
        assert!(keypair.is_ok());

        let keypair = keypair.unwrap();
        assert_eq!(keypair.bit_length(), 512);
        assert!(keypair.public_key.n > from_u64(0));
        assert!(keypair.private_key.d > from_u64(0));
    }

    #[test]
    fn test_key_encrypt_decrypt() {
        let keypair = generate_keypair(512, 65537).unwrap();
        let message = b"Hello, RSA!";

        let ciphertext = keypair.public_key.encrypt(message).unwrap();
        let decrypted = keypair.private_key.decrypt(&ciphertext).unwrap();

        assert_eq!(message.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_key_properties() {
        let keypair = generate_keypair(512, 17).unwrap();

        // Verify n = p * q
        assert_eq!(keypair.private_key.n, keypair.private_key.p * keypair.private_key.q);

        // Verify e * d ≡ 1 (mod φ(n))
        let phi_n = (&keypair.private_key.p - 1u8) * (&keypair.private_key.q - 1u8);
        let one = from_u64(1);
        let product = &keypair.public_key.e * &keypair.private_key.d;
        let remainder = product % &phi_n;
        assert_eq!(remainder, one);
    }
}
