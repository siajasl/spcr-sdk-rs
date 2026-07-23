//! # spcr-utils-crypto
//!
//! Cryptographic utilities for the Spacer SDK.
//!
//! This crate is intentionally minimal to begin with; functionality will be
//! added as the SDK grows.

pub mod digests;
pub mod sigs;

/// Returns the name of this crate.
///
/// Placeholder used to verify the crate is wired into the workspace correctly.
pub fn name() -> &'static str {
    "spcr-utils-crypto"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_correct() {
        assert_eq!(name(), "spcr-utils-crypto");
    }
}
