// RSA Big Integer Operations
// Wrapper around num-bigint for RSA-specific operations

use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_integer::Integer;
use num_traits::{One, Zero, Pow};
use rand::thread_rng;
use std::fmt;

/// RSA Big Integer type alias
pub type RsaBigInt = BigUint;

/// Create a big integer from u64
pub fn from_u64(n: u64) -> RsaBigInt {
    RsaBigInt::from(n)
}

/// Create a big integer from bytes (big-endian)
pub fn from_bytes(bytes: &[u8]) -> RsaBigInt {
    RsaBigInt::from_bytes_be(bytes)
}

/// Convert big integer to bytes (big-endian)
pub fn to_bytes(n: &RsaBigInt) -> Vec<u8> {
    n.to_bytes_be()
}

/// Modular exponentiation: base^exp mod modulus
/// Uses square-and-multiply algorithm
pub fn mod_pow(base: &RsaBigInt, exp: &RsaBigInt, modulus: &RsaBigInt) -> RsaBigInt {
    if modulus.is_one() {
        return RsaBigInt::zero();
    }

    let mut result = RsaBigInt::one();
    let mut base = base % modulus;
    let mut exp = exp.clone();

    while !exp.is_zero() {
        if exp.is_odd() {
            result = (&result * &base) % modulus;
        }
        base = (&base * &base) % modulus;
        exp >>= 1;
    }

    result
}

/// Extended Euclidean Algorithm
/// Returns (gcd, x, y) such that a*x + b*y = gcd = gcd(a, b)
pub fn extended_gcd(a: &RsaBigInt, b: &RsaBigInt) -> (RsaBigInt, RsaBigInt, RsaBigInt) {
    if b.is_zero() {
        return (a.clone(), RsaBigInt::one(), RsaBigInt::zero());
    }

    let (gcd, x1, y1) = extended_gcd(b, &(a % b));
    let x = y1.clone();
    let y = x1 - (a / b) * &y1;

    (gcd, x, y)
}

/// Compute modular inverse: a^(-1) mod m
/// Returns None if inverse doesn't exist
pub fn mod_inverse(a: &RsaBigInt, m: &RsaBigInt) -> Option<RsaBigInt> {
    let (gcd, x, _) = extended_gcd(a, m);

    if gcd != RsaBigInt::one() {
        // Inverse doesn't exist
        return None;
    }

    let mut result = x % m;
    if result.is_zero() {
        result = m.clone() - RsaBigInt::one();
    } else if result < RsaBigInt::zero() {
        result = result + m.clone();
    }

    Some(result)
}

/// Miller-Rabin primality test
/// Returns true if n is probably prime
pub fn is_probable_prime(n: &RsaBigInt, iterations: u32) -> bool {
    if n < &RsaBigInt::from(2u8) {
        return false;
    }
    if n == &RsaBigInt::from(2u8) || n == &RsaBigInt::from(3u8) {
        return true;
    }
    if n.is_even() {
        return false;
    }

    // Write n-1 as d * 2^s with d odd
    let mut d = n.clone() - 1u8;
    let mut s = 0u32;
    while d.is_even() {
        d >>= 1;
        s += 1;
    }

    // Witness loop
    let mut rng = thread_rng();
    let two = RsaBigInt::from(2u8);
    let n_minus_two = n - RsaBigInt::from(2u8);

    for _ in 0..iterations {
        // Pick random witness a in [2, n-2]
        let a = rng.gen_biguint_range(&two, &n_minus_two);

        // Compute x = a^d mod n
        let mut x = mod_pow(&a, &d, n);

        if x == RsaBigInt::one() || x == n - 1u8 {
            continue;
        }

        let mut continue_outer = false;
        for _ in 1..s {
            x = mod_pow(&x, &two, n);
            if x == n - 1u8 {
                continue_outer = true;
                break;
            }
        }

        if continue_outer {
            continue;
        }

        // Composite
        return false;
    }

    // Probably prime
    true
}

/// Generate a random big integer in range [0, bound)
pub fn random_biguint(bound: &RsaBigInt) -> RsaBigInt {
    let mut rng = thread_rng();
    rng.gen_biguint_below(bound)
}

/// Generate a random prime of specified bit length
pub fn random_prime(bit_length: u32) -> RsaBigInt {
    let mut rng = thread_rng();
    let mut prime;

    loop {
        // Generate random number with specified bit length
        let lower = RsaBigInt::from(1u8) << (bit_length - 1);
        let upper = (RsaBigInt::from(1u8) << bit_length) - 1u8;

        prime = rng.gen_biguint_range(&lower, &upper);

        // Make it odd
        if prime.is_even() {
            prime += 1u8;
        }

        // Check primality
        if is_probable_prime(&prime, 10) {
            break;
        }
    }

    prime
}

/// Greatest common divisor
pub fn gcd(a: &RsaBigInt, b: &RsaBigInt) -> RsaBigInt {
    a.gcd(b)
}

/// Least common multiple
pub fn lcm(a: &RsaBigInt, b: &RsaBigInt) -> RsaBigInt {
    if a.is_zero() || b.is_zero() {
        return RsaBigInt::zero();
    }
    (a * b) / gcd(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mod_pow() {
        // 3^5 mod 7 = 243 mod 7 = 5
        let base = from_u64(3);
        let exp = from_u64(5);
        let modulus = from_u64(7);
        let result = mod_pow(&base, &exp, &modulus);
        assert_eq!(result, from_u64(5));
    }

    #[test]
    fn test_mod_inverse() {
        // 3 * 5 = 15 ≡ 1 mod 7, so inverse of 3 mod 7 is 5
        let a = from_u64(3);
        let m = from_u64(7);
        let inv = mod_inverse(&a, &m).unwrap();
        assert_eq!(inv, from_u64(5));

        // Verify: 3 * 5 = 15 ≡ 1 (mod 7)
        assert_eq!((a * inv) % m, from_u64(1));
    }

    #[test]
    fn test_is_probable_prime() {
        // 2 is prime
        assert!(is_probable_prime(&from_u64(2), 5));
        // 3 is prime
        assert!(is_probable_prime(&from_u64(3), 5));
        // 7 is prime
        assert!(is_probable_prime(&from_u64(7), 5));
        // 4 is not prime
        assert!(!is_probable_prime(&from_u64(4), 5));
        // 9 is not prime
        assert!(!is_probable_prime(&from_u64(9), 5));
    }
}
