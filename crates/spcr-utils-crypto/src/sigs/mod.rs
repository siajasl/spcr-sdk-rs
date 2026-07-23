//! Digital signature verification utilities.
//!
//! Each supported signature algorithm lives in its own submodule. The
//! verification functions and their associated length constants are re-exported
//! here so callers can reach them directly as `sigs::verify_signature_*`.

mod ed25519;
mod secp256k1;

pub use ed25519::{
    verify_signature_ed25519_over_prehash, ED25519_DIGEST_LENGTH, ED25519_SIGNATURE_LENGTH,
    ED25519_VERIFYING_KEY_LENGTH,
};
pub use secp256k1::{
    verify_signature_secp256k1_over_prehash, SECP256K1_DIGEST_LENGTH, SECP256K1_SIGNATURE_LENGTH,
    SECP256K1_VERIFYING_KEY_LENGTH,
};
