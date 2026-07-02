//! AEAD (AES-256-GCM, ChaCha20-Poly1305) over AWS-LC, exposed across the C-ABI.
//!
//! Wire format = `ciphertext || tag(16)` with a 12-byte nonce — identical to
//! pqforge's `PqSymmetricPrimitives.aesGcmEncrypt`, so sealed data is
//! cross-backend interoperable.
//!
//! SECURITY:
//! * AES-GCM nonce reuse under one key is catastrophic. This primitive faithfully
//!   uses the caller-supplied nonce; **nonce uniqueness is the caller's
//!   responsibility** (the STREAM framing layer, blueprint §8.3, derives per-frame
//!   nonces from a counter). `LessSafeKey` is used because it accepts an explicit
//!   nonce; it is therefore outside the FIPS-approved nonce-management path.
//! * `open` releases plaintext ONLY after the tag verifies; a tag failure returns
//!   `AuthFailed` and never yields unauthenticated bytes.
//! * The plaintext recovered by `open` lives in a `Zeroizing` buffer, wiped on
//!   drop; AWS-LC zeroizes its internal key copy on drop.

use std::os::raw::c_int;
use std::slice;

use aws_lc_rs::aead::{
    Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305,
};
use zeroize::Zeroizing;

use crate::error::{finish, guard, write_out, PqForgeError, PqForgeStatus};

/// AEAD tag length (bytes) for the supported suites.
const TAG_LEN: usize = 16;

/// Maps the Dart-side AEAD id to an AWS-LC algorithm. `0` = AES-256-GCM.
fn aead_alg(id: c_int) -> Option<&'static Algorithm> {
    match id {
        0 => Some(&AES_256_GCM),
        1 => Some(&CHACHA20_POLY1305),
        _ => None,
    }
}

/// Seals `plaintext` under `key`/`nonce` with associated data `aad`, writing
/// `ciphertext || tag` (length = `plaintext_len + 16`) into the caller buffer.
///
/// # Safety
/// Every `*const` pointer must be valid for its length (or null with len 0);
/// `ct_out`/`ct_len` valid per `ct_cap`.
#[no_mangle]
pub unsafe extern "C" fn pqforge_aead_seal(
    alg_id: c_int,
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ct_out: *mut u8,
    ct_cap: usize,
    ct_len: *mut usize,
) -> c_int {
    finish(guard(|| {
        let alg = match aead_alg(alg_id) {
            Some(a) => a,
            None => return Ok(PqForgeStatus::InvalidKey),
        };
        if key.is_null()
            || nonce.is_null()
            || (aad.is_null() && aad_len != 0)
            || (plaintext.is_null() && plaintext_len != 0)
        {
            return Ok(PqForgeStatus::NullArgument);
        }
        // SAFETY: each non-null pointer is valid for its length per the contract.
        let key_slice = unsafe { slice::from_raw_parts(key, key_len) };
        let nonce_slice = unsafe { slice::from_raw_parts(nonce, nonce_len) };
        let aad_slice = unsafe { empty_or(aad, aad_len) };
        let pt_slice = unsafe { empty_or(plaintext, plaintext_len) };

        let sealing = match make_key(alg, key_slice) {
            Some(k) => k,
            None => return Ok(PqForgeStatus::InvalidKey),
        };
        let nonce_obj = match Nonce::try_assume_unique_for_key(nonce_slice) {
            Ok(n) => n,
            Err(_) => return Ok(PqForgeStatus::InvalidKey),
        };

        // Encrypt in place; the buffer transitions plaintext -> ciphertext, then
        // the 16-byte tag is appended.
        let mut in_out = pt_slice.to_vec();
        sealing
            .seal_in_place_append_tag(nonce_obj, Aad::from(aad_slice), &mut in_out)
            .map_err(|_| PqForgeError::Internal("AEAD seal failed".into()))?;

        // SAFETY: caller buffer per contract.
        let s = unsafe { write_out(&in_out, ct_out, ct_cap, ct_len) };
        Ok(s)
    }))
}

/// Opens `ciphertext || tag` under `key`/`nonce`/`aad`, writing the verified
/// plaintext (length = `ciphertext_len - 16`) into the caller buffer.
///
/// Returns `AuthFailed` (3) on tag failure, `InvalidCiphertext` (2) if the input
/// is shorter than a tag, `InvalidKey` (1) for bad key/nonce/algorithm.
///
/// # Safety
/// As for [`pqforge_aead_seal`].
#[no_mangle]
pub unsafe extern "C" fn pqforge_aead_open(
    alg_id: c_int,
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    pt_out: *mut u8,
    pt_cap: usize,
    pt_len: *mut usize,
) -> c_int {
    finish(guard(|| {
        let alg = match aead_alg(alg_id) {
            Some(a) => a,
            None => return Ok(PqForgeStatus::InvalidKey),
        };
        if key.is_null() || nonce.is_null() || ciphertext.is_null() || (aad.is_null() && aad_len != 0)
        {
            return Ok(PqForgeStatus::NullArgument);
        }
        if ciphertext_len < TAG_LEN {
            return Ok(PqForgeStatus::InvalidCiphertext);
        }
        // SAFETY: each non-null pointer is valid for its length per the contract.
        let key_slice = unsafe { slice::from_raw_parts(key, key_len) };
        let nonce_slice = unsafe { slice::from_raw_parts(nonce, nonce_len) };
        let aad_slice = unsafe { empty_or(aad, aad_len) };
        let ct_slice = unsafe { slice::from_raw_parts(ciphertext, ciphertext_len) };

        let opening = match make_key(alg, key_slice) {
            Some(k) => k,
            None => return Ok(PqForgeStatus::InvalidKey),
        };
        let nonce_obj = match Nonce::try_assume_unique_for_key(nonce_slice) {
            Ok(n) => n,
            Err(_) => return Ok(PqForgeStatus::InvalidKey),
        };

        // The recovered plaintext is secret: hold it in a zeroized buffer.
        let mut in_out = Zeroizing::new(ct_slice.to_vec());
        let plaintext = match opening.open_in_place(
            nonce_obj,
            Aad::from(aad_slice),
            in_out.as_mut_slice(),
        ) {
            Ok(pt) => pt,
            // Tag verification failed — never release unauthenticated bytes.
            Err(_) => return Ok(PqForgeStatus::AuthFailed),
        };

        // SAFETY: caller buffer per contract.
        let s = unsafe { write_out(plaintext, pt_out, pt_cap, pt_len) };
        Ok(s)
    }))
}

fn make_key(alg: &'static Algorithm, key: &[u8]) -> Option<LessSafeKey> {
    UnboundKey::new(alg, key).ok().map(LessSafeKey::new)
}

/// Returns an empty slice when `len == 0`, else the pointed-to slice.
///
/// # Safety
/// If `len != 0`, `ptr` must be non-null and valid for `len` bytes.
unsafe fn empty_or<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALG: c_int = 0; // AES-256-GCM

    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> (i32, Vec<u8>) {
        let mut ct = vec![0u8; pt.len() + TAG_LEN + 16];
        let mut cl = 0usize;
        let rc = unsafe {
            pqforge_aead_seal(
                ALG, key.as_ptr(), key.len(), nonce.as_ptr(), nonce.len(), aad.as_ptr(),
                aad.len(), pt.as_ptr(), pt.len(), ct.as_mut_ptr(), ct.len(), &mut cl,
            )
        };
        if rc == PqForgeStatus::Ok.code() {
            ct.truncate(cl);
        } else {
            ct.clear();
        }
        (rc, ct)
    }

    fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> (i32, Vec<u8>) {
        let mut pt = vec![0u8; ct.len()];
        let mut pl = 0usize;
        let rc = unsafe {
            pqforge_aead_open(
                ALG, key.as_ptr(), key.len(), nonce.as_ptr(), nonce.len(), aad.as_ptr(),
                aad.len(), ct.as_ptr(), ct.len(), pt.as_mut_ptr(), pt.len(), &mut pl,
            )
        };
        if rc == PqForgeStatus::Ok.code() {
            pt.truncate(pl);
        } else {
            pt.clear();
        }
        (rc, pt)
    }

    #[test]
    fn seal_open_round_trip() {
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let aad = b"header";
        let pt = b"top secret payload";
        let (rc, ct) = seal(&key, &nonce, aad, pt);
        assert_eq!(rc, PqForgeStatus::Ok.code());
        assert_eq!(ct.len(), pt.len() + TAG_LEN);
        let (rc, out) = open(&key, &nonce, aad, &ct);
        assert_eq!(rc, PqForgeStatus::Ok.code());
        assert_eq!(out, pt);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let (rc, ct) = seal(&key, &nonce, b"", b"");
        assert_eq!(rc, PqForgeStatus::Ok.code());
        assert_eq!(ct.len(), TAG_LEN);
        let (rc, out) = open(&key, &nonce, b"", &ct);
        assert_eq!(rc, PqForgeStatus::Ok.code());
        assert!(out.is_empty());
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let (_, mut ct) = seal(&key, &nonce, b"", b"data");
        ct[0] ^= 0xFF;
        let (rc, out) = open(&key, &nonce, b"", &ct);
        assert_eq!(rc, PqForgeStatus::AuthFailed.code());
        assert!(out.is_empty(), "no plaintext released on auth failure");
    }

    #[test]
    fn wrong_aad_fails_authentication() {
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let (_, ct) = seal(&key, &nonce, b"aad-A", b"data");
        let (rc, _) = open(&key, &nonce, b"aad-B", &ct);
        assert_eq!(rc, PqForgeStatus::AuthFailed.code());
    }

    #[test]
    fn wrong_key_length_is_invalid_key() {
        // 16 bytes is invalid for AES-256.
        let (rc, _) = seal(&[7u8; 16], &[3u8; 12], b"", b"x");
        assert_eq!(rc, PqForgeStatus::InvalidKey.code());
    }

    #[test]
    fn short_ciphertext_is_invalid() {
        let (rc, _) = open(&[7u8; 32], &[3u8; 12], b"", &[0u8; 8]);
        assert_eq!(rc, PqForgeStatus::InvalidCiphertext.code());
    }

    #[test]
    fn chacha20_poly1305_round_trip_and_tamper() {
        const CHACHA: c_int = 1;
        let key = [9u8; 32];
        let nonce = [4u8; 12];
        let aad = b"chacha-aad";
        let pt = b"chacha20-poly1305 payload";

        let mut ct = vec![0u8; pt.len() + TAG_LEN + 16];
        let mut cl = 0usize;
        let rc = unsafe {
            pqforge_aead_seal(
                CHACHA, key.as_ptr(), key.len(), nonce.as_ptr(), nonce.len(), aad.as_ptr(),
                aad.len(), pt.as_ptr(), pt.len(), ct.as_mut_ptr(), ct.len(), &mut cl,
            )
        };
        assert_eq!(rc, PqForgeStatus::Ok.code());
        ct.truncate(cl);
        assert_eq!(ct.len(), pt.len() + TAG_LEN);

        let mut out = vec![0u8; ct.len()];
        let mut ol = 0usize;
        let rc = unsafe {
            pqforge_aead_open(
                CHACHA, key.as_ptr(), key.len(), nonce.as_ptr(), nonce.len(), aad.as_ptr(),
                aad.len(), ct.as_ptr(), ct.len(), out.as_mut_ptr(), out.len(), &mut ol,
            )
        };
        assert_eq!(rc, PqForgeStatus::Ok.code());
        out.truncate(ol);
        assert_eq!(out, pt);

        ct[0] ^= 0xFF;
        let rc = unsafe {
            pqforge_aead_open(
                CHACHA, key.as_ptr(), key.len(), nonce.as_ptr(), nonce.len(), aad.as_ptr(),
                aad.len(), ct.as_ptr(), ct.len(), out.as_mut_ptr(), out.len(), &mut ol,
            )
        };
        assert_eq!(rc, PqForgeStatus::AuthFailed.code());
    }
}
