//! Phase 2 cryptographic core over `aws-lc-rs` (AWS-LC / BoringSSL lineage).
//!
//! This module begins by confirming AWS-LC links and runs in this environment
//! (settles evidence item E6) with a stable SHA-256 probe, before the ML-KEM /
//! ML-DSA surface is wired in. The probe is also exposed over the C-ABI so Dart
//! can confirm the accelerated backend is genuinely live, not merely loaded.

mod kem;
mod sign;

use std::os::raw::c_int;

use aws_lc_rs::digest::{digest, SHA256};

use crate::error::{guard, PqForgeStatus};

/// True if AWS-LC is linked and its SHA-256 yields a 32-byte digest.
pub fn aws_lc_live() -> bool {
    digest(&SHA256, b"pqforge").as_ref().len() == 32
}

/// Returns `Ok` (0) if the native crypto core (AWS-LC) is linked and live, else
/// `Internal` (9). Panic-guarded; no panic can escape.
#[no_mangle]
pub extern "C" fn pqforge_crypto_selftest() -> c_int {
    guard(|| {
        Ok(if aws_lc_live() {
            PqForgeStatus::Ok
        } else {
            PqForgeStatus::Internal
        })
    })
    .unwrap_or(PqForgeStatus::Internal)
    .code() as c_int
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_lc_links_and_digests() {
        assert!(aws_lc_live());
    }
}
