//! secp256k1 ECDSA signature verification.

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;

/// Length, in bytes, of a secp256k1 ECDSA signature (compact `r || s`).
pub const SECP256K1_SIGNATURE_LENGTH: usize = 64;

/// Length, in bytes, of a secp256k1 signing (private) key scalar.
pub const SECP256K1_SIGNING_KEY_LENGTH: usize = 32;

/// Length, in bytes, of a compressed (SEC1) secp256k1 verification key.
pub const SECP256K1_VERIFYING_KEY_LENGTH: usize = 33;

/// Length, in bytes, of the pre-hashed message digest verified against a
/// secp256k1 signature.
pub const SECP256K1_DIGEST_LENGTH: usize = 32;

/// Generates a new secp256k1 key pair, returning `(signing_key, verifying_key)`
/// as raw bytes.
///
/// If `seed` is `Some`, it is interpreted as the 32-byte big-endian private key
/// scalar and the pair is derived deterministically; the returned signing key
/// equals the seed. If `seed` is `None`, a fresh key is drawn from the operating
/// system's cryptographically secure random number generator ([`OsRng`]).
///
/// The first element of the returned tuple is the 32-byte signing (private) key
/// scalar; the second is the corresponding 33-byte compressed (SEC1)
/// verification (public) key.
///
/// # Panics
///
/// Panics if `seed` is `Some` but does not encode a valid secp256k1 scalar
/// (i.e. it is zero or greater than or equal to the curve order).
///
/// # Examples
///
/// ```
/// # use spcr_utils_crypto::sigs::new_key_pair_secp256k1;
/// // Deriving from a fixed, valid scalar is deterministic.
/// let seed = [7u8; 32];
/// let (signing_key, verifying_key) = new_key_pair_secp256k1(Some(&seed));
/// assert_eq!(signing_key, seed);
/// assert_eq!(new_key_pair_secp256k1(Some(&seed)), (signing_key, verifying_key));
/// ```
pub fn new_key_pair_secp256k1(
    seed: Option<&[u8; SECP256K1_SIGNING_KEY_LENGTH]>,
) -> (
    [u8; SECP256K1_SIGNING_KEY_LENGTH],
    [u8; SECP256K1_VERIFYING_KEY_LENGTH],
) {
    let signing_key = match seed {
        Some(seed) => SigningKey::from_slice(seed).expect("seed is a valid secp256k1 scalar"),
        None => SigningKey::random(&mut OsRng),
    };
    let signing_key_bytes: [u8; SECP256K1_SIGNING_KEY_LENGTH] = signing_key.to_bytes().into();
    let verifying_key_bytes: [u8; SECP256K1_VERIFYING_KEY_LENGTH] = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed key is 33 bytes");
    (signing_key_bytes, verifying_key_bytes)
}

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

    #[test]
    fn new_key_pair_from_seed_is_deterministic() {
        let seed = [7u8; SECP256K1_SIGNING_KEY_LENGTH];
        assert_eq!(
            new_key_pair_secp256k1(Some(&seed)),
            new_key_pair_secp256k1(Some(&seed))
        );
    }

    #[test]
    fn new_key_pair_returns_seed_as_signing_key() {
        let seed = [7u8; SECP256K1_SIGNING_KEY_LENGTH];
        let (private_key, public_key) = new_key_pair_secp256k1(Some(&seed));
        assert_eq!(private_key, seed);
        // The verifying key matches the compressed key k256 derives from the seed.
        let expected = SigningKey::from_slice(&seed).expect("valid scalar");
        assert_eq!(public_key, vkey_bytes(&expected));
    }

    #[test]
    fn new_key_pair_produces_verifiable_signatures() {
        let (signing_key, verifying_key) = new_key_pair_secp256k1(None);
        let key = SigningKey::from_slice(&signing_key).expect("generated scalar is valid");
        let digest = [3u8; SECP256K1_DIGEST_LENGTH];
        let sig = sign(&key, &digest);
        assert!(verify_signature_secp256k1_over_prehash(
            &sig,
            &verifying_key,
            &digest,
        ));
    }

    #[test]
    fn new_random_key_pairs_differ() {
        assert_ne!(new_key_pair_secp256k1(None), new_key_pair_secp256k1(None));
    }

    #[test]
    #[should_panic]
    fn new_key_pair_panics_on_invalid_seed() {
        // An all-zero scalar is not a valid secp256k1 private key.
        let _ = new_key_pair_secp256k1(Some(&[0u8; SECP256K1_SIGNING_KEY_LENGTH]));
    }
}
