//! secp256k1 ECDSA signature verification.

use std::path::Path;

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::pkcs8::DecodePrivateKey;
use rand_core::OsRng;
use sec1::DecodeEcPrivateKey;

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

/// An error returned by [`get_key_pair_from_bytes_secp256k1`].
#[derive(Debug)]
pub enum Secp256k1KeyBytesError {
    /// The bytes do not encode a valid secp256k1 private key scalar (i.e. the
    /// scalar is zero or greater than or equal to the curve order).
    InvalidScalar,
}

impl std::fmt::Display for Secp256k1KeyBytesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidScalar => f.write_str(
                "bytes do not encode a valid secp256k1 private key scalar \
                 (must be non-zero and less than the curve order)",
            ),
        }
    }
}

impl std::error::Error for Secp256k1KeyBytesError {}

/// Derives a secp256k1 key pair from a raw private key, returning
/// `(signing_key, verifying_key)` as raw bytes.
///
/// `private_key` is a 32-byte big-endian private key scalar. The returned
/// signing key equals `private_key`, and the 33-byte compressed (SEC1)
/// verification (public) key is derived from it.
///
/// Unlike [`new_key_pair_secp256k1`], which panics on an invalid seed, this
/// function reports an invalid scalar via its return type.
///
/// # Errors
///
/// Returns [`Secp256k1KeyBytesError::InvalidScalar`] if `private_key` is not a
/// valid secp256k1 scalar (i.e. it is zero or greater than or equal to the
/// curve order).
///
/// # Examples
///
/// ```
/// # use spcr_utils_crypto::sigs::get_key_pair_from_bytes_secp256k1;
/// let private_key = [7u8; 32];
/// let (signing_key, verifying_key) = get_key_pair_from_bytes_secp256k1(&private_key)?;
/// assert_eq!(signing_key, private_key);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn get_key_pair_from_bytes_secp256k1(
    private_key: &[u8; SECP256K1_SIGNING_KEY_LENGTH],
) -> Result<
    (
        [u8; SECP256K1_SIGNING_KEY_LENGTH],
        [u8; SECP256K1_VERIFYING_KEY_LENGTH],
    ),
    Secp256k1KeyBytesError,
> {
    let signing_key =
        SigningKey::from_slice(private_key).map_err(|_| Secp256k1KeyBytesError::InvalidScalar)?;
    let signing_key_bytes: [u8; SECP256K1_SIGNING_KEY_LENGTH] = signing_key.to_bytes().into();
    let verifying_key_bytes: [u8; SECP256K1_VERIFYING_KEY_LENGTH] = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed key is 33 bytes");
    Ok((signing_key_bytes, verifying_key_bytes))
}

/// An error returned by [`get_key_pair_from_pem_secp256k1`].
#[derive(Debug)]
pub enum Secp256k1PemError {
    /// The PEM file could not be read from disk.
    Io(std::io::Error),
    /// The file contents could not be parsed as a supported PEM-encoded
    /// secp256k1 private key (PKCS#8 or SEC1).
    Parse,
}

impl std::fmt::Display for Secp256k1PemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "failed to read PEM file: {err}"),
            Self::Parse => f.write_str(
                "file is not a valid PEM-encoded secp256k1 private key (expected PKCS#8 or SEC1)",
            ),
        }
    }
}

impl std::error::Error for Secp256k1PemError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Parse => None,
        }
    }
}

impl From<std::io::Error> for Secp256k1PemError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Loads a secp256k1 key pair from a PEM file at `path`, returning
/// `(signing_key, verifying_key)` as raw bytes.
///
/// The file must contain a PEM-encoded secp256k1 private key in either PKCS#8
/// (`-----BEGIN PRIVATE KEY-----`) or SEC1 (`-----BEGIN EC PRIVATE KEY-----`)
/// form. The public key is derived from the private scalar.
///
/// The first element of the returned tuple is the 32-byte signing (private) key
/// scalar; the second is the corresponding 33-byte compressed (SEC1)
/// verification (public) key.
///
/// # Errors
///
/// Returns [`Secp256k1PemError::Io`] if the file cannot be read, or
/// [`Secp256k1PemError::Parse`] if its contents are not a valid PEM-encoded
/// secp256k1 private key.
///
/// # Examples
///
/// ```no_run
/// # use spcr_utils_crypto::sigs::get_key_pair_from_pem_secp256k1;
/// let (private_key, public_key) = get_key_pair_from_pem_secp256k1("key.pem")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn get_key_pair_from_pem_secp256k1(
    path: impl AsRef<Path>,
) -> Result<
    (
        [u8; SECP256K1_SIGNING_KEY_LENGTH],
        [u8; SECP256K1_VERIFYING_KEY_LENGTH],
    ),
    Secp256k1PemError,
> {
    let pem = std::fs::read_to_string(path)?;
    let signing_key = SigningKey::from_pkcs8_pem(&pem)
        .or_else(|_| SigningKey::from_sec1_pem(&pem))
        .map_err(|_| Secp256k1PemError::Parse)?;
    let signing_key_bytes: [u8; SECP256K1_SIGNING_KEY_LENGTH] = signing_key.to_bytes().into();
    let verifying_key_bytes: [u8; SECP256K1_VERIFYING_KEY_LENGTH] = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed key is 33 bytes");
    Ok((signing_key_bytes, verifying_key_bytes))
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
/// # use spcr_utils_crypto::sigs::verify_signature_over_prehash_secp256k1;
/// // An all-zero key/signature does not verify an arbitrary digest.
/// assert!(!verify_signature_over_prehash_secp256k1(&[0u8; 64], &[0u8; 33], &[0u8; 32]));
/// ```
pub fn verify_signature_over_prehash_secp256k1(
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
        assert!(verify_signature_over_prehash_secp256k1(
            &sig,
            &vkey_bytes(&key),
            &digest
        ));
    }

    #[test]
    fn rejects_signature_over_wrong_digest() {
        let key = signing_key();
        let sig = sign(&key, &[3u8; SECP256K1_DIGEST_LENGTH]);
        assert!(!verify_signature_over_prehash_secp256k1(
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
        assert!(!verify_signature_over_prehash_secp256k1(
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
        assert!(!verify_signature_over_prehash_secp256k1(
            &sig,
            &[0u8; SECP256K1_VERIFYING_KEY_LENGTH],
            &digest,
        ));
    }

    #[test]
    fn rejects_all_zero_inputs() {
        assert!(!verify_signature_over_prehash_secp256k1(
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
        assert!(verify_signature_over_prehash_secp256k1(
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

    #[test]
    fn from_bytes_returns_private_key_and_derived_public() {
        let private_key = [7u8; SECP256K1_SIGNING_KEY_LENGTH];
        let (signing_key_bytes, public_key) =
            get_key_pair_from_bytes_secp256k1(&private_key).expect("valid scalar");
        assert_eq!(signing_key_bytes, private_key);
        assert_eq!(public_key, vkey_bytes(&signing_key()));
    }

    #[test]
    fn from_bytes_matches_new_key_pair_with_seed() {
        let private_key = [7u8; SECP256K1_SIGNING_KEY_LENGTH];
        assert_eq!(
            get_key_pair_from_bytes_secp256k1(&private_key).expect("valid scalar"),
            new_key_pair_secp256k1(Some(&private_key))
        );
    }

    #[test]
    fn from_bytes_produces_verifiable_signatures() {
        let private_key = [7u8; SECP256K1_SIGNING_KEY_LENGTH];
        let (signing_key_bytes, public_key) =
            get_key_pair_from_bytes_secp256k1(&private_key).expect("valid scalar");
        let key = SigningKey::from_slice(&signing_key_bytes).expect("valid scalar");
        let digest = [3u8; SECP256K1_DIGEST_LENGTH];
        let sig = sign(&key, &digest);
        assert!(verify_signature_over_prehash_secp256k1(
            &sig,
            &public_key,
            &digest,
        ));
    }

    #[test]
    fn from_bytes_rejects_invalid_scalar() {
        // An all-zero scalar is not a valid secp256k1 private key.
        let err = get_key_pair_from_bytes_secp256k1(&[0u8; SECP256K1_SIGNING_KEY_LENGTH])
            .expect_err("all-zero scalar must error");
        assert!(matches!(err, Secp256k1KeyBytesError::InvalidScalar));
    }

    /// A unique temp-file path for a PEM fixture, scoped to this process and a
    /// per-call counter so parallel tests never collide.
    fn temp_pem_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "spcr_secp256k1_{}_{}_{}.pem",
            tag,
            std::process::id(),
            n
        ))
    }

    #[test]
    fn loads_pkcs8_pem_key_pair() {
        use k256::pkcs8::{EncodePrivateKey, LineEnding};
        let key = signing_key();
        let pem = key.to_pkcs8_pem(LineEnding::LF).expect("encode PKCS#8 PEM");
        let path = temp_pem_path("pkcs8");
        std::fs::write(&path, pem.as_bytes()).expect("write PEM fixture");

        let (private_key, public_key) =
            get_key_pair_from_pem_secp256k1(&path).expect("load PKCS#8 key pair");
        std::fs::remove_file(&path).ok();

        assert_eq!(private_key, [7u8; SECP256K1_SIGNING_KEY_LENGTH]);
        assert_eq!(public_key, vkey_bytes(&key));
    }

    #[test]
    fn loads_sec1_pem_key_pair() {
        use sec1::{der::pem::LineEnding, EncodeEcPrivateKey};
        let key = signing_key();
        let pem = key.to_sec1_pem(LineEnding::LF).expect("encode SEC1 PEM");
        let path = temp_pem_path("sec1");
        std::fs::write(&path, pem.as_bytes()).expect("write PEM fixture");

        let (private_key, public_key) =
            get_key_pair_from_pem_secp256k1(&path).expect("load SEC1 key pair");
        std::fs::remove_file(&path).ok();

        assert_eq!(private_key, [7u8; SECP256K1_SIGNING_KEY_LENGTH]);
        assert_eq!(public_key, vkey_bytes(&key));
    }

    #[test]
    fn errors_on_missing_file() {
        let path = temp_pem_path("missing");
        let err = get_key_pair_from_pem_secp256k1(&path).expect_err("missing file must error");
        assert!(matches!(err, Secp256k1PemError::Io(_)));
    }

    #[test]
    fn errors_on_invalid_pem() {
        let path = temp_pem_path("garbage");
        std::fs::write(&path, b"not a pem file").expect("write garbage fixture");
        let err = get_key_pair_from_pem_secp256k1(&path).expect_err("garbage must error");
        std::fs::remove_file(&path).ok();
        assert!(matches!(err, Secp256k1PemError::Parse));
    }
}
