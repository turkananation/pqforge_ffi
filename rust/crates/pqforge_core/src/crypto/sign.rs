//! ML-DSA (FIPS 204) over AWS-LC, exposed across the C-ABI.
//!
//! aws-lc-rs exposes ML-DSA in raw FIPS-204 form — `from_raw_private_key`,
//! `private_key().as_raw_bytes()`, and the raw public key via
//! `public_key().as_ref()` — so keys and signatures interoperate with the
//! pure-Dart `pqforge` fallback with no ASN.1/PKCS8 conversion. Secret material
//! that transits Rust is wrapped in [`zeroize::Zeroizing`].

use std::os::raw::c_int;
use std::slice;

use aws_lc_rs::encoding::AsRawBytes;
use aws_lc_rs::signature::{KeyPair, UnparsedPublicKey};
use aws_lc_rs::unstable::signature::{
    PqdsaKeyPair, ML_DSA_44, ML_DSA_44_SIGNING, ML_DSA_65, ML_DSA_65_SIGNING, ML_DSA_87, ML_DSA_87_SIGNING,
};
use zeroize::Zeroizing;

use crate::error::{finish, guard, write_out, PqForgeError, PqForgeStatus};

/// Generates an ML-DSA key pair, writing raw FIPS-204 public and secret keys
/// into the caller buffers. `alg_id` 0/1/2 = ML-DSA-44/65/87 (matches the Dart
/// `PqSignatureAlgorithm.index`).
///
/// # Safety
/// All `out`/`len` pointers must be valid for their capacities (or null).
#[no_mangle]
pub unsafe extern "C" fn pqforge_mldsa_keygen(
    alg_id: c_int,
    pub_out: *mut u8,
    pub_cap: usize,
    pub_len: *mut usize,
    sec_out: *mut u8,
    sec_cap: usize,
    sec_len: *mut usize,
) -> c_int {
    finish(guard(|| {
        let kp = match alg_id {
            0 => PqdsaKeyPair::generate(&ML_DSA_44_SIGNING),
            1 => PqdsaKeyPair::generate(&ML_DSA_65_SIGNING),
            2 => PqdsaKeyPair::generate(&ML_DSA_87_SIGNING),
            _ => return Ok(PqForgeStatus::InvalidKey),
        }
        .map_err(|_| PqForgeError::Internal("ML-DSA keygen failed".into()))?;

        let pub_bytes = kp.public_key().as_ref();
        let raw_secret = kp
            .private_key()
            .as_raw_bytes()
            .map_err(|_| PqForgeError::Internal("export raw secret key failed".into()))?;
        let secret = Zeroizing::new(raw_secret.as_ref().to_vec());

        // SAFETY: caller buffers per the function contract.
        let s1 = unsafe { write_out(pub_bytes, pub_out, pub_cap, pub_len) };
        if s1 != PqForgeStatus::Ok {
            return Ok(s1);
        }
        let s2 = unsafe { write_out(&secret, sec_out, sec_cap, sec_len) };
        Ok(s2)
    }))
}

/// Signs `msg` with a raw ML-DSA secret key, writing the signature into the
/// caller buffer (size = the algorithm's `signature_len`).
///
/// # Safety
/// `seckey`/`msg` must be valid for their lengths; out/len pointers valid per cap.
#[no_mangle]
pub unsafe extern "C" fn pqforge_mldsa_sign(
    alg_id: c_int,
    seckey: *const u8,
    seckey_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
    sig_cap: usize,
    sig_len: *mut usize,
) -> c_int {
    finish(guard(|| {
        if seckey.is_null() || (msg.is_null() && msg_len != 0) {
            return Ok(PqForgeStatus::NullArgument);
        }
        // SAFETY: non-null/length-checked per contract.
        let sec_slice = unsafe { slice::from_raw_parts(seckey, seckey_len) };
        let msg_slice = if msg_len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(msg, msg_len) }
        };

        let kp = match alg_id {
            0 => PqdsaKeyPair::from_raw_private_key(&ML_DSA_44_SIGNING, sec_slice),
            1 => PqdsaKeyPair::from_raw_private_key(&ML_DSA_65_SIGNING, sec_slice),
            2 => PqdsaKeyPair::from_raw_private_key(&ML_DSA_87_SIGNING, sec_slice),
            _ => return Ok(PqForgeStatus::InvalidKey),
        };
        let kp = match kp {
            Ok(k) => k,
            Err(_) => return Ok(PqForgeStatus::InvalidKey),
        };

        let needed = kp.algorithm().signature_len();
        let mut signature = vec![0u8; needed];
        kp.sign(msg_slice, &mut signature)
            .map_err(|_| PqForgeError::Internal("ML-DSA sign failed".into()))?;

        // SAFETY: caller buffer per contract.
        let s = unsafe { write_out(&signature, sig_out, sig_cap, sig_len) };
        Ok(s)
    }))
}

/// Verifies a signature with a raw ML-DSA public key. Returns `Ok` (0) if valid,
/// `AuthFailed` (3) if the signature is well-formed but invalid, `InvalidKey`
/// (1) for an unknown algorithm, `NullArgument` (10) for a null pointer.
///
/// # Safety
/// `pubkey`/`msg`/`sig` must be valid for their lengths (or null with len 0).
#[no_mangle]
pub unsafe extern "C" fn pqforge_mldsa_verify(
    alg_id: c_int,
    pubkey: *const u8,
    pubkey_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> c_int {
    finish(guard(|| {
        if pubkey.is_null() || sig.is_null() || (msg.is_null() && msg_len != 0) {
            return Ok(PqForgeStatus::NullArgument);
        }
        // SAFETY: non-null/length-checked per contract.
        let pub_slice = unsafe { slice::from_raw_parts(pubkey, pubkey_len) };
        let sig_slice = unsafe { slice::from_raw_parts(sig, sig_len) };
        let msg_slice = if msg_len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(msg, msg_len) }
        };

        let verified = match alg_id {
            0 => UnparsedPublicKey::new(&ML_DSA_44, pub_slice).verify(msg_slice, sig_slice),
            1 => UnparsedPublicKey::new(&ML_DSA_65, pub_slice).verify(msg_slice, sig_slice),
            2 => UnparsedPublicKey::new(&ML_DSA_87, pub_slice).verify(msg_slice, sig_slice),
            _ => return Ok(PqForgeStatus::InvalidKey),
        };
        Ok(if verified.is_ok() {
            PqForgeStatus::Ok
        } else {
            PqForgeStatus::AuthFailed
        })
    }))
}

/// Deterministically generates an ML-DSA key pair from a 32-byte seed
/// (FIPS 204 `KeyGen(ξ)`). The same seed always yields the same key pair —
/// the basis for known-answer and cross-implementation equivalence tests.
/// Returns `InvalidKey` for an unknown algorithm or a seed of the wrong length.
///
/// # Safety
/// `seed` must be valid for `seed_len` reads; out/len pointers valid per cap.
#[no_mangle]
pub unsafe extern "C" fn pqforge_mldsa_keygen_from_seed(
    alg_id: c_int,
    seed: *const u8,
    seed_len: usize,
    pub_out: *mut u8,
    pub_cap: usize,
    pub_len: *mut usize,
    sec_out: *mut u8,
    sec_cap: usize,
    sec_len: *mut usize,
) -> c_int {
    finish(guard(|| {
        if seed.is_null() {
            return Ok(PqForgeStatus::NullArgument);
        }
        // SAFETY: non-null, valid for seed_len per contract.
        let seed_slice = unsafe { slice::from_raw_parts(seed, seed_len) };
        let kp = match alg_id {
            0 => PqdsaKeyPair::from_seed(&ML_DSA_44_SIGNING, seed_slice),
            1 => PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed_slice),
            2 => PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, seed_slice),
            _ => return Ok(PqForgeStatus::InvalidKey),
        };
        let kp = match kp {
            Ok(k) => k,
            Err(_) => return Ok(PqForgeStatus::InvalidKey),
        };
        let pub_bytes = kp.public_key().as_ref();
        let raw_secret = kp
            .private_key()
            .as_raw_bytes()
            .map_err(|_| PqForgeError::Internal("export raw secret key failed".into()))?;
        let secret = Zeroizing::new(raw_secret.as_ref().to_vec());

        // SAFETY: caller buffers per contract.
        let s1 = unsafe { write_out(pub_bytes, pub_out, pub_cap, pub_len) };
        if s1 != PqForgeStatus::Ok {
            return Ok(s1);
        }
        let s2 = unsafe { write_out(&secret, sec_out, sec_cap, sec_len) };
        Ok(s2)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ML-DSA-65 raw sizes (FIPS 204).
    const ALG: c_int = 1;
    const PK: usize = 1952;
    const SK: usize = 4032;
    const SIG: usize = 3309;

    fn keygen() -> (Vec<u8>, Vec<u8>) {
        // Generous buffers so we observe the true emitted lengths.
        let mut pk = vec![0u8; PK + 64];
        let mut sk = vec![0u8; SK + 64];
        let (mut pl, mut sl) = (0usize, 0usize);
        let rc = unsafe {
            pqforge_mldsa_keygen(
                ALG,
                pk.as_mut_ptr(),
                pk.len(),
                &mut pl,
                sk.as_mut_ptr(),
                sk.len(),
                &mut sl,
            )
        };
        assert_eq!(rc, PqForgeStatus::Ok.code());
        assert_eq!((pl, sl), (PK, SK), "aws-lc raw ML-DSA-65 key sizes must match FIPS 204");
        pk.truncate(pl);
        sk.truncate(sl);
        (pk, sk)
    }

    #[test]
    fn keygen_sign_verify_round_trip() {
        let (pk, sk) = keygen();
        let msg = b"pqforge ML-DSA self-test";

        let mut sig = vec![0u8; SIG];
        let mut sigl = 0usize;
        let rc = unsafe {
            pqforge_mldsa_sign(
                ALG,
                sk.as_ptr(),
                sk.len(),
                msg.as_ptr(),
                msg.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut sigl,
            )
        };
        assert_eq!(rc, PqForgeStatus::Ok.code());
        assert_eq!(sigl, SIG);

        let rc = unsafe {
            pqforge_mldsa_verify(ALG, pk.as_ptr(), pk.len(), msg.as_ptr(), msg.len(), sig.as_ptr(), SIG)
        };
        assert_eq!(rc, PqForgeStatus::Ok.code());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let (pk, sk) = keygen();
        let msg = b"original message";
        let mut sig = vec![0u8; SIG];
        let mut sigl = 0usize;
        unsafe {
            pqforge_mldsa_sign(
                ALG, sk.as_ptr(), sk.len(), msg.as_ptr(), msg.len(), sig.as_mut_ptr(), sig.len(),
                &mut sigl,
            );
        }
        let bad = b"tampered message";
        let rc = unsafe {
            pqforge_mldsa_verify(ALG, pk.as_ptr(), pk.len(), bad.as_ptr(), bad.len(), sig.as_ptr(), SIG)
        };
        assert_eq!(rc, PqForgeStatus::AuthFailed.code());
    }

    #[test]
    fn unknown_algorithm_is_invalid_key() {
        let mut pk = vec![0u8; 3000];
        let mut sk = vec![0u8; 5000];
        let (mut pl, mut sl) = (0usize, 0usize);
        let rc = unsafe {
            pqforge_mldsa_keygen(99, pk.as_mut_ptr(), 3000, &mut pl, sk.as_mut_ptr(), 5000, &mut sl)
        };
        assert_eq!(rc, PqForgeStatus::InvalidKey.code());
    }

    #[test]
    fn keygen_from_seed_is_deterministic() {
        fn pub_from_seed(seed: &[u8]) -> Vec<u8> {
            let mut pk = vec![0u8; PK + 64];
            let mut sk = vec![0u8; SK + 64];
            let (mut pl, mut sl) = (0usize, 0usize);
            let rc = unsafe {
                pqforge_mldsa_keygen_from_seed(
                    ALG,
                    seed.as_ptr(),
                    seed.len(),
                    pk.as_mut_ptr(),
                    pk.len(),
                    &mut pl,
                    sk.as_mut_ptr(),
                    sk.len(),
                    &mut sl,
                )
            };
            assert_eq!(rc, PqForgeStatus::Ok.code());
            pk.truncate(pl);
            pk
        }

        let seed = [7u8; 32];
        assert_eq!(pub_from_seed(&seed), pub_from_seed(&seed), "same seed → same key");
        assert_ne!(
            pub_from_seed(&seed),
            pub_from_seed(&[9u8; 32]),
            "different seed → different key"
        );

        // A wrong-length seed is rejected as InvalidKey.
        let mut pk = vec![0u8; PK + 64];
        let mut sk = vec![0u8; SK + 64];
        let (mut pl, mut sl) = (0usize, 0usize);
        let short = [0u8; 31];
        let rc = unsafe {
            pqforge_mldsa_keygen_from_seed(
                ALG, short.as_ptr(), short.len(), pk.as_mut_ptr(), pk.len(), &mut pl,
                sk.as_mut_ptr(), sk.len(), &mut sl,
            )
        };
        assert_eq!(rc, PqForgeStatus::InvalidKey.code());
    }
}
