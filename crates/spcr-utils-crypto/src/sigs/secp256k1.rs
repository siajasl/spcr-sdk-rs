//! secp256k1 ECDSA signature verification.

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};

/// Length, in bytes, of a secp256k1 ECDSA signature (compact `r || s`).
pub const SECP256K1_SIGNATURE_LENGTH: usize = 64;

/// Length, in bytes, of a compressed (SEC1) secp256k1 verification key.
pub const SECP256K1_VERIFYING_KEY_LENGTH: usize = 33;

/// Length, in bytes, of the pre-hashed message digest verified against a
/// secp256k1 signature.
pub const SECP256K1_DIGEST_LENGTH: usize = 32;

/// Verifies a secp256k1 ECDSA `sig` over the pre-hashed message digest `msg`
/// for the given verification key `vkey`.
///
/// `msg` is a 32-byte digest that the caller has already computed (for example
/// with [`crate::digests`]); this function does **not** hash the message. `sig`
/// is a compact `r || s` signature and `vkey` is a compressed (SEC1) key.
///
/// Returns `true` if, and only if, the signature is valid for the digest under
/// the supplied key. Returns `false` if verification fails, if `vkey` is not a
/// valid compressed secp256k1 key, or if `sig` is not a well-formed signature.
///
/// # Examples
///
/// ```
/// # use spcr_utils_crypto::sigs::verify_signature_secp256k1_over_prehash;
/// // An all-zero key/signature does not verify an arbitrary digest.
/// assert!(!verify_signature_secp256k1_over_prehash(&[0u8; 64], &[0u8; 33], &[0u8; 32]));
/// ```
pub fn verify_signature_secp256k1_over_prehash(
    sig: &[u8; SECP256K1_SIGNATURE_LENGTH],
    vkey: &[u8; SECP256K1_VERIFYING_KEY_LENGTH],
    msg: &[u8; SECP256K1_DIGEST_LENGTH],
) -> bool {
    let verifying_key = match VerifyingKey::from_sec1_bytes(vkey) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let signature = match Signature::from_slice(sig) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    verifying_key.verify_prehash(msg, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey;

    /// A deterministic signing key derived from a fixed seed, for reproducible
    /// tests.
    fn signing_key() -> SigningKey {
        SigningKey::from_slice(&[7u8; 32]).expect("valid secp256k1 scalar")
    }

    /// The compressed (33-byte) verification key for `key`.
    fn vkey_bytes(key: &SigningKey) -> [u8; SECP256K1_VERIFYING_KEY_LENGTH] {
        let point = key.verifying_key().to_encoded_point(true);
        point
            .as_bytes()
            .try_into()
            .expect("compressed key is 33 bytes")
    }

    /// A compact (64-byte) signature over `digest` produced by `key`.
    fn sign(key: &SigningKey, digest: &[u8; SECP256K1_DIGEST_LENGTH]) -> [u8; 64] {
        let sig: Signature = key.sign_prehash(digest).expect("signing a 32-byte digest");
        sig.to_bytes().into()
    }

    #[test]
    fn accepts_valid_signature() {
        let key = signing_key();
        let digest = [3u8; SECP256K1_DIGEST_LENGTH];
        let sig = sign(&key, &digest);
        assert!(verify_signature_secp256k1_over_prehash(
            &sig,
            &vkey_bytes(&key),
            &digest
        ));
    }

    #[test]
    fn rejects_signature_over_wrong_digest() {
        let key = signing_key();
        let sig = sign(&key, &[3u8; SECP256K1_DIGEST_LENGTH]);
        assert!(!verify_signature_secp256k1_over_prehash(
            &sig,
            &vkey_bytes(&key),
            &[4u8; SECP256K1_DIGEST_LENGTH],
        ));
    }

    #[test]
    fn rejects_signature_under_wrong_key() {
        let key = signing_key();
        let other = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let digest = [3u8; SECP256K1_DIGEST_LENGTH];
        let sig = sign(&key, &digest);
        assert!(!verify_signature_secp256k1_over_prehash(
            &sig,
            &vkey_bytes(&other),
            &digest,
        ));
    }

    #[test]
    fn rejects_malformed_key() {
        // `0x00` is not a valid SEC1 prefix, so the key fails to decode.
        let key = signing_key();
        let digest = [3u8; SECP256K1_DIGEST_LENGTH];
        let sig = sign(&key, &digest);
        assert!(!verify_signature_secp256k1_over_prehash(
            &sig,
            &[0u8; SECP256K1_VERIFYING_KEY_LENGTH],
            &digest,
        ));
    }

    #[test]
    fn rejects_all_zero_inputs() {
        assert!(!verify_signature_secp256k1_over_prehash(
            &[0u8; 64], &[0u8; 33], &[0u8; 32],
        ));
    }
}
