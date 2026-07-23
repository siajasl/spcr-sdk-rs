//! Ed25519 signature verification.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Length, in bytes, of an Ed25519 signature.
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

/// Length, in bytes, of an Ed25519 verification (public) key.
pub const ED25519_VERIFYING_KEY_LENGTH: usize = 32;

/// Length, in bytes, of the pre-hashed message digest verified against an
/// Ed25519 signature.
pub const ED25519_DIGEST_LENGTH: usize = 32;

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
}
