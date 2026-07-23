//! Cryptographic digest (hashing) utilities.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

/// Default output length, in bytes, of a BLAKE2b hash.
pub const BLAKE2B_DEFAULT_HASH_LENGTH: usize = 32;

/// Hashes `data` with the BLAKE2b algorithm, producing a
/// [`BLAKE2B_DEFAULT_HASH_LENGTH`]-byte (32-byte) digest.
///
/// # Examples
///
/// ```
/// let digest = spcr_utils_crypto::digests::get_hash_blake2b(b"spacer");
/// assert_eq!(digest.len(), 32);
/// ```
pub fn get_hash_blake2b(data: &[u8]) -> [u8; BLAKE2B_DEFAULT_HASH_LENGTH] {
    let mut digest = [0u8; BLAKE2B_DEFAULT_HASH_LENGTH];
    let bytes = get_hash_blake2b_of_length(data, BLAKE2B_DEFAULT_HASH_LENGTH);
    digest.copy_from_slice(&bytes);
    digest
}

/// Hashes `data` with the BLAKE2b algorithm, producing a digest of `length`
/// bytes.
///
/// # Panics
///
/// Panics if `length` is `0` or greater than `64` (the maximum output length
/// supported by BLAKE2b).
///
/// # Examples
///
/// ```
/// let digest = spcr_utils_crypto::digests::get_hash_blake2b_of_length(b"spacer", 16);
/// assert_eq!(digest.len(), 16);
/// ```
pub fn get_hash_blake2b_of_length(data: &[u8], length: usize) -> Vec<u8> {
    assert!(
        (1..=64).contains(&length),
        "BLAKE2b output length must be between 1 and 64 bytes inclusive, got {length}"
    );
    let mut hasher = Blake2bVar::new(length).expect("length already validated to be within 1..=64");
    hasher.update(data);
    hasher.finalize_boxed().into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2b_default_length_is_32_bytes() {
        assert_eq!(get_hash_blake2b(b"spacer").len(), 32);
    }

    #[test]
    fn blake2b_matches_known_vector() {
        // BLAKE2b-256 of the empty input (RFC 7693 parameterisation).
        let expected = [
            0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2, 0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99,
            0xda, 0xa1, 0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87, 0xfa, 0xab, 0x45, 0xcd,
            0xf1, 0x2f, 0xe3, 0xa8,
        ];
        assert_eq!(get_hash_blake2b(b""), expected);
    }

    #[test]
    fn blake2b_is_deterministic() {
        assert_eq!(get_hash_blake2b(b"spacer"), get_hash_blake2b(b"spacer"));
    }

    #[test]
    fn blake2b_of_length_honours_requested_length() {
        assert_eq!(get_hash_blake2b_of_length(b"spacer", 16).len(), 16);
        assert_eq!(get_hash_blake2b_of_length(b"spacer", 64).len(), 64);
    }

    #[test]
    #[should_panic]
    fn blake2b_of_length_rejects_zero_length() {
        let _ = get_hash_blake2b_of_length(b"spacer", 0);
    }
}
