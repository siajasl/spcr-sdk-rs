//! Ed25519 signature verification.

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

/// Length, in bytes, of an Ed25519 signature.
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

/// Length, in bytes, of an Ed25519 signing (private) key seed.
pub const ED25519_SIGNING_KEY_LENGTH: usize = 32;

/// Length, in bytes, of an Ed25519 verification (public) key.
pub const ED25519_VERIFYING_KEY_LENGTH: usize = 32;

/// Length, in bytes, of the pre-hashed message digest verified against an
/// Ed25519 signature.
pub const ED25519_DIGEST_LENGTH: usize = 32;

/// Generates a new Ed25519 key pair, returning `(signing_key, verifying_key)`
/// as raw bytes.
///
/// If `seed` is `Some`, the key pair is derived deterministically from those 32
/// bytes; the returned signing key equals the seed. If `seed` is `None`, a fresh
/// seed is drawn from the operating system's cryptographically secure random
/// number generator ([`OsRng`]).
///
/// The first element of the returned tuple is the 32-byte signing (private) key
/// seed; the second is the corresponding 32-byte verification (public) key.
///
/// # Examples
///
/// ```
/// # use spcr_utils_crypto::sigs::new_key_pair_ed25519;
/// // Deriving from a fixed seed is deterministic.
/// let seed = [7u8; 32];
/// let (signing_key, verifying_key) = new_key_pair_ed25519(Some(&seed));
/// assert_eq!(signing_key, seed);
/// assert_eq!(new_key_pair_ed25519(Some(&seed)), (signing_key, verifying_key));
/// ```
pub fn new_key_pair_ed25519(
    seed: Option<&[u8; ED25519_SIGNING_KEY_LENGTH]>,
) -> (
    [u8; ED25519_SIGNING_KEY_LENGTH],
    [u8; ED25519_VERIFYING_KEY_LENGTH],
) {
    let signing_key = match seed {
        Some(seed) => SigningKey::from_bytes(seed),
        None => SigningKey::generate(&mut OsRng),
    };
    (
        signing_key.to_bytes(),
        signing_key.verifying_key().to_bytes(),
    )
}

/// Verifies an Ed25519 `sig` over the pre-hashed message digest `msg` for the
/// given verification key `vkey`.
///
/// `msg` is a 32-byte digest that the caller has already computed (for example
/// with [`crate::digests`]); this function does **not** hash the message. The
/// digest is verified as the message of a "pure" Ed25519 signature (RFC 8032),
/// i.e. the signer is expected to have signed these 32 bytes directly. This is
/// distinct from the Ed25519ph pre-hash construction, which applies additional
/// domain separation and is not used here.
///
/// Returns `true` if, and only if, the signature is valid for the digest under
/// the supplied key. Returns `false` if verification fails or if `vkey` is not a
/// valid Ed25519 verification key (i.e. it does not decode to a point on the
/// curve).
///
/// # Examples
///
/// ```
/// # use spcr_utils_crypto::sigs::verify_signature_ed25519_over_prehash;
/// // An all-zero key/signature does not verify an arbitrary digest.
/// assert!(!verify_signature_ed25519_over_prehash(&[0u8; 64], &[0u8; 32], &[0u8; 32]));
/// ```
pub fn verify_signature_ed25519_over_prehash(
    sig: &[u8; ED25519_SIGNATURE_LENGTH],
    vkey: &[u8; ED25519_VERIFYING_KEY_LENGTH],
    msg: &[u8; ED25519_DIGEST_LENGTH],
) -> bool {
    let verifying_key = match VerifyingKey::from_bytes(vkey) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(sig);
    verifying_key.verify(msg, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// A deterministic signing key derived from a fixed seed, for reproducible
    /// tests.
    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn accepts_valid_signature() {
        let key = signing_key();
        let digest = [3u8; ED25519_DIGEST_LENGTH];
        let sig = key.sign(&digest);
        assert!(verify_signature_ed25519_over_prehash(
            &sig.to_bytes(),
            &key.verifying_key().to_bytes(),
            &digest,
        ));
    }

    #[test]
    fn rejects_signature_over_wrong_digest() {
        let key = signing_key();
        let sig = key.sign(&[3u8; ED25519_DIGEST_LENGTH]);
        assert!(!verify_signature_ed25519_over_prehash(
            &sig.to_bytes(),
            &key.verifying_key().to_bytes(),
            &[4u8; ED25519_DIGEST_LENGTH],
        ));
    }

    #[test]
    fn rejects_signature_under_wrong_key() {
        let key = signing_key();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let digest = [3u8; ED25519_DIGEST_LENGTH];
        let sig = key.sign(&digest);
        assert!(!verify_signature_ed25519_over_prehash(
            &sig.to_bytes(),
            &other.verifying_key().to_bytes(),
            &digest,
        ));
    }

    #[test]
    fn rejects_all_zero_inputs() {
        assert!(!verify_signature_ed25519_over_prehash(
            &[0u8; 64],
            &[0u8; 32],
            &[0u8; 32],
        ));
    }

    #[test]
    fn new_key_pair_from_seed_is_deterministic() {
        let seed = [42u8; ED25519_SIGNING_KEY_LENGTH];
        assert_eq!(new_key_pair_ed25519(Some(&seed)), new_key_pair_ed25519(Some(&seed)));
    }

    #[test]
    fn new_key_pair_returns_seed_as_signing_key() {
        let seed = [42u8; ED25519_SIGNING_KEY_LENGTH];
        let (signing_key, verifying_key) = new_key_pair_ed25519(Some(&seed));
        assert_eq!(signing_key, seed);
        // The verifying key matches the one dalek derives from the same seed.
        let expected = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        assert_eq!(verifying_key, expected);
    }

    #[test]
    fn new_key_pair_produces_verifiable_signatures() {
        let (signing_key, verifying_key) = new_key_pair_ed25519(None);
        let digest = [3u8; ED25519_DIGEST_LENGTH];
        let sig = SigningKey::from_bytes(&signing_key).sign(&digest);
        assert!(verify_signature_ed25519_over_prehash(
            &sig.to_bytes(),
            &verifying_key,
            &digest,
        ));
    }

    #[test]
    fn new_random_key_pairs_differ() {
        assert_ne!(new_key_pair_ed25519(None), new_key_pair_ed25519(None));
    }
}
