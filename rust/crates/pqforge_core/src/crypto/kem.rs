//! ML-KEM (FIPS 203) over AWS-LC, exposed across the C-ABI.
//!
//! Keys, ciphertexts, and shared secrets are raw FIPS-203 bytes, so they
//! interoperate with the pure-Dart `pqforge` fallback (cross-backend
//! equivalence is proven in the Dart tests). Secret material that transits Rust
//! is wrapped in [`zeroize::Zeroizing`] so the Rust-side copy is wiped on drop.

use std::os::raw::c_int;
use std::slice;

use aws_lc_rs::kem::{
    Algorithm, AlgorithmId, Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024,
    ML_KEM_512, ML_KEM_768,
};
use zeroize::Zeroizing;

use crate::error::{finish, guard, write_out, PqForgeError, PqForgeStatus};

/// Maps the Dart-side algorithm id (0/1/2) to an AWS-LC ML-KEM algorithm.
/// Ids match `PqKemAlgorithm.index` on the Dart side (mlKem512/768/1024).
fn kem_alg(id: c_int) -> Option<&'static Algorithm<AlgorithmId>> {
    match id {
        0 => Some(&ML_KEM_512),
        1 => Some(&ML_KEM_768),
        2 => Some(&ML_KEM_1024),
        _ => None,
    }
}

/// Generates an ML-KEM key pair, writing the raw public and secret keys into the
/// caller buffers. Returns `Ok`; `InvalidKey` for an unknown `alg_id`;
/// `BufferTooSmall`/`NullArgument` on buffer problems (with `*_len` set);
/// `Internal` on an AWS-LC error or caught panic.
///
/// # Safety
/// All `out`/`len` pointers must be valid for their declared capacities (or null).
#[no_mangle]
pub unsafe extern "C" fn pqforge_mlkem_keygen(
    alg_id: c_int,
    pub_out: *mut u8,
    pub_cap: usize,
    pub_len: *mut usize,
    sec_out: *mut u8,
    sec_cap: usize,
    sec_len: *mut usize,
) -> c_int {
    finish(guard(|| {
        let alg = match kem_alg(alg_id) {
            Some(a) => a,
            None => return Ok(PqForgeStatus::InvalidKey),
        };
        let dk = DecapsulationKey::generate(alg)
            .map_err(|_| PqForgeError::Internal("ML-KEM keygen failed".into()))?;
        let ek = dk
            .encapsulation_key()
            .map_err(|_| PqForgeError::Internal("derive encapsulation key failed".into()))?;
        let pub_bytes = ek
            .key_bytes()
            .map_err(|_| PqForgeError::Internal("export public key failed".into()))?;
        let sec_bytes = dk
            .key_bytes()
            .map_err(|_| PqForgeError::Internal("export secret key failed".into()))?;
        // Wipe the Rust-side secret-key copy on drop.
        let secret = Zeroizing::new(sec_bytes.as_ref().to_vec());

        // SAFETY: caller-provided buffers per the function contract.
        let s1 = unsafe { write_out(pub_bytes.as_ref(), pub_out, pub_cap, pub_len) };
        if s1 != PqForgeStatus::Ok {
            return Ok(s1);
        }
        let s2 = unsafe { write_out(&secret, sec_out, sec_cap, sec_len) };
        Ok(s2)
    }))
}

/// Encapsulates to a raw ML-KEM public key, writing the ciphertext and shared
/// secret into the caller buffers.
///
/// # Safety
/// `pubkey` must be valid for `pubkey_len` reads; out/len pointers valid per cap.
#[no_mangle]
pub unsafe extern "C" fn pqforge_mlkem_encapsulate(
    alg_id: c_int,
    pubkey: *const u8,
    pubkey_len: usize,
    ct_out: *mut u8,
    ct_cap: usize,
    ct_len: *mut usize,
    ss_out: *mut u8,
    ss_cap: usize,
    ss_len: *mut usize,
) -> c_int {
    finish(guard(|| {
        let alg = match kem_alg(alg_id) {
            Some(a) => a,
            None => return Ok(PqForgeStatus::InvalidKey),
        };
        if pubkey.is_null() {
            return Ok(PqForgeStatus::NullArgument);
        }
        // SAFETY: pubkey non-null, valid for pubkey_len reads per contract.
        let pub_slice = unsafe { slice::from_raw_parts(pubkey, pubkey_len) };
        let ek = match EncapsulationKey::new(alg, pub_slice) {
            Ok(k) => k,
            Err(_) => return Ok(PqForgeStatus::InvalidKey),
        };
        let (ciphertext, shared) = ek
            .encapsulate()
            .map_err(|_| PqForgeError::Internal("ML-KEM encapsulate failed".into()))?;
        let secret = Zeroizing::new(shared.as_ref().to_vec());

        // SAFETY: caller buffers per contract.
        let s1 = unsafe { write_out(ciphertext.as_ref(), ct_out, ct_cap, ct_len) };
        if s1 != PqForgeStatus::Ok {
            return Ok(s1);
        }
        let s2 = unsafe { write_out(&secret, ss_out, ss_cap, ss_len) };
        Ok(s2)
    }))
}

/// Decapsulates a ciphertext with a raw ML-KEM secret key, writing the shared
/// secret into the caller buffer. ML-KEM uses implicit rejection: a corrupt
/// ciphertext yields a *different* secret rather than an error.
///
/// # Safety
/// `seckey`/`ct` must be valid for their lengths; out/len pointers valid per cap.
#[no_mangle]
pub unsafe extern "C" fn pqforge_mlkem_decapsulate(
    alg_id: c_int,
    seckey: *const u8,
    seckey_len: usize,
    ct: *const u8,
    ct_len: usize,
    ss_out: *mut u8,
    ss_cap: usize,
    ss_len: *mut usize,
) -> c_int {
    finish(guard(|| {
        let alg = match kem_alg(alg_id) {
            Some(a) => a,
            None => return Ok(PqForgeStatus::InvalidKey),
        };
        if seckey.is_null() || ct.is_null() {
            return Ok(PqForgeStatus::NullArgument);
        }
        // SAFETY: non-null, valid for their lengths per contract.
        let sec_slice = unsafe { slice::from_raw_parts(seckey, seckey_len) };
        let ct_slice = unsafe { slice::from_raw_parts(ct, ct_len) };
        let dk = match DecapsulationKey::new(alg, sec_slice) {
            Ok(k) => k,
            Err(_) => return Ok(PqForgeStatus::InvalidKey),
        };
        let shared = dk
            .decapsulate(Ciphertext::from(ct_slice))
            .map_err(|_| PqForgeError::InvalidCiphertext)?;
        let secret = Zeroizing::new(shared.as_ref().to_vec());

        // SAFETY: caller buffer per contract.
        let s = unsafe { write_out(&secret, ss_out, ss_cap, ss_len) };
        Ok(s)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ML-KEM-768 raw sizes (FIPS 203).
    const ALG: c_int = 1;
    const PK: usize = 1184;
    const SK: usize = 2400;
    const CT: usize = 1088;
    const SS: usize = 32;

    #[test]
    fn keygen_encapsulate_decapsulate_round_trip() {
        let mut pk = vec![0u8; PK];
        let mut sk = vec![0u8; SK];
        let (mut pl, mut sl) = (0usize, 0usize);
        let rc = unsafe {
            pqforge_mlkem_keygen(
                ALG,
                pk.as_mut_ptr(),
                PK,
                &mut pl,
                sk.as_mut_ptr(),
                SK,
                &mut sl,
            )
        };
        assert_eq!(rc, PqForgeStatus::Ok.code());
        assert_eq!((pl, sl), (PK, SK));

        let mut ct = vec![0u8; CT];
        let mut ss1 = vec![0u8; SS];
        let (mut cl, mut s1l) = (0usize, 0usize);
        let rc = unsafe {
            pqforge_mlkem_encapsulate(
                ALG,
                pk.as_ptr(),
                PK,
                ct.as_mut_ptr(),
                CT,
                &mut cl,
                ss1.as_mut_ptr(),
                SS,
                &mut s1l,
            )
        };
        assert_eq!(rc, PqForgeStatus::Ok.code());
        assert_eq!((cl, s1l), (CT, SS));

        let mut ss2 = vec![0u8; SS];
        let mut s2l = 0usize;
        let rc = unsafe {
            pqforge_mlkem_decapsulate(
                ALG,
                sk.as_ptr(),
                SK,
                ct.as_ptr(),
                CT,
                ss2.as_mut_ptr(),
                SS,
                &mut s2l,
            )
        };
        assert_eq!(rc, PqForgeStatus::Ok.code());
        assert_eq!(ss1, ss2, "encapsulated and decapsulated secrets must match");
    }

    #[test]
    fn buffer_too_small_reports_required_length() {
        let mut pk = vec![0u8; 10];
        let mut sk = vec![0u8; SK];
        let (mut pl, mut sl) = (0usize, 0usize);
        let rc = unsafe {
            pqforge_mlkem_keygen(ALG, pk.as_mut_ptr(), 10, &mut pl, sk.as_mut_ptr(), SK, &mut sl)
        };
        assert_eq!(rc, PqForgeStatus::BufferTooSmall.code());
        assert_eq!(pl, PK);
    }

    #[test]
    fn unknown_algorithm_is_invalid_key() {
        let mut pk = vec![0u8; 2000];
        let mut sk = vec![0u8; 4000];
        let (mut pl, mut sl) = (0usize, 0usize);
        let rc = unsafe {
            pqforge_mlkem_keygen(99, pk.as_mut_ptr(), 2000, &mut pl, sk.as_mut_ptr(), 4000, &mut sl)
        };
        assert_eq!(rc, PqForgeStatus::InvalidKey.code());
    }
}
