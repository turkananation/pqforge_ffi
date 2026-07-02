//! X25519 key agreement + Ed25519 signatures over AWS-LC, across the C-ABI.
//!
//! These are the classical half of the hybrid stack — the native backend for
//! pqforge's `PqClassicalProvider` seam. X25519 (RFC 7748) and Ed25519
//! (RFC 8032) are deterministic, so native output is **byte-identical** to the
//! pure-Dart `package:cryptography` provider: seeded keygen, ECDH, public-key
//! derivation, and signatures all match bit-for-bit (proven by the cross-impl
//! conformance harness on the Dart side).
//!
//! A private key here is its raw 32-byte seed/scalar — the same convention as
//! `package:cryptography` (whose X25519/Ed25519 secret bytes *are* the seed) —
//! so keys interoperate with the fallback with no PKCS8/DER conversion. Secret
//! material transiting Rust is wrapped in [`zeroize::Zeroizing`].
//!
//! **ECDSA-P256 is intentionally absent:** aws-lc-rs exposes no raw-scalar-only
//! `EcdsaKeyPair` constructor (only `from_private_key_and_public_key`,
//! `from_private_key_der`, `from_pkcs8`), so deriving a public point from a bare
//! 32-byte scalar would need low-level EC_POINT FFI. The native classical
//! provider therefore routes ECDSA-P256 to the pure-Dart fallback.

use std::os::raw::c_int;
use std::slice;

use aws_lc_rs::agreement::{agree, PrivateKey, UnparsedPublicKey as AgreementPublicKey, X25519};
use aws_lc_rs::rand;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use zeroize::Zeroizing;

use crate::error::{finish, guard, write_out, PqForgeError, PqForgeStatus};

const X25519_KEY_LEN: usize = 32;
const ED25519_SEED_LEN: usize = 32;
const ED25519_PUBLIC_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;

/// Generates an X25519 key pair. If `seed` is null a fresh 32-byte private key
/// is drawn from the AWS-LC CSPRNG; otherwise `seed` (which must be 32 bytes) is
/// used as the private key, giving deterministic keygen. The 32-byte public key
/// and the 32-byte private key (its own seed) are written to the caller buffers.
///
/// # Safety
/// `seed` valid for `seed_len` reads (or null); out/len pointers valid per cap.
#[no_mangle]
pub unsafe extern "C" fn pqforge_x25519_keygen(
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
        // The X25519 private key is 32 bytes: a caller seed, or fresh randomness.
        let mut secret = Zeroizing::new(vec![0u8; X25519_KEY_LEN]);
        if seed.is_null() {
            rand::fill(&mut secret[..])
                .map_err(|_| PqForgeError::Internal("x25519 rng failed".into()))?;
        } else {
            if seed_len != X25519_KEY_LEN {
                return Ok(PqForgeStatus::InvalidKey);
            }
            // SAFETY: non-null, valid for seed_len per contract.
            let s = unsafe { slice::from_raw_parts(seed, seed_len) };
            secret.copy_from_slice(s);
        }

        let private = PrivateKey::from_private_key(&X25519, &secret[..])
            .map_err(|_| PqForgeError::InvalidKey("x25519 private key rejected".into()))?;
        let public = private
            .compute_public_key()
            .map_err(|_| PqForgeError::Internal("x25519 public key failed".into()))?;

        // SAFETY: caller buffers per contract.
        let s1 = unsafe { write_out(public.as_ref(), pub_out, pub_cap, pub_len) };
        if s1 != PqForgeStatus::Ok {
            return Ok(s1);
        }
        let s2 = unsafe { write_out(&secret[..], sec_out, sec_cap, sec_len) };
        Ok(s2)
    }))
}

/// X25519 ECDH: mixes a 32-byte private key with a 32-byte peer public key and
/// writes the 32-byte shared secret. Returns `InvalidKey` for a wrong-length key
/// or a rejected/low-order peer point.
///
/// # Safety
/// `secret`/`peer_pub` valid for their lengths; out/len pointers valid per cap.
#[no_mangle]
pub unsafe extern "C" fn pqforge_x25519_ecdh(
    secret: *const u8,
    secret_len: usize,
    peer_pub: *const u8,
    peer_pub_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    finish(guard(|| {
        if secret.is_null() || peer_pub.is_null() {
            return Ok(PqForgeStatus::NullArgument);
        }
        if secret_len != X25519_KEY_LEN || peer_pub_len != X25519_KEY_LEN {
            return Ok(PqForgeStatus::InvalidKey);
        }
        // SAFETY: non-null, length-checked per contract.
        let sec = unsafe { slice::from_raw_parts(secret, secret_len) };
        let peer = unsafe { slice::from_raw_parts(peer_pub, peer_pub_len) };

        let private = PrivateKey::from_private_key(&X25519, sec)
            .map_err(|_| PqForgeError::InvalidKey("x25519 private key rejected".into()))?;
        let shared = agree(
            &private,
            AgreementPublicKey::new(&X25519, peer),
            PqForgeError::InvalidKey("x25519 ecdh failed".into()),
            |ss| Ok::<Vec<u8>, PqForgeError>(ss.to_vec()),
        )?;
        let shared = Zeroizing::new(shared);

        // SAFETY: caller buffer per contract.
        let s = unsafe { write_out(&shared[..], out, out_cap, out_len) };
        Ok(s)
    }))
}

/// Generates an Ed25519 key pair. If `seed` is null a fresh 32-byte seed is
/// drawn from the CSPRNG; otherwise `seed` (32 bytes) is used, giving
/// deterministic keygen. Writes the 32-byte public key and the 32-byte secret
/// key (the seed itself, matching the pure-Dart provider).
///
/// # Safety
/// `seed` valid for `seed_len` reads (or null); out/len pointers valid per cap.
#[no_mangle]
pub unsafe extern "C" fn pqforge_ed25519_keygen(
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
        let mut seed_buf = Zeroizing::new(vec![0u8; ED25519_SEED_LEN]);
        if seed.is_null() {
            rand::fill(&mut seed_buf[..])
                .map_err(|_| PqForgeError::Internal("ed25519 rng failed".into()))?;
        } else {
            if seed_len != ED25519_SEED_LEN {
                return Ok(PqForgeStatus::InvalidKey);
            }
            // SAFETY: non-null, valid for seed_len per contract.
            let s = unsafe { slice::from_raw_parts(seed, seed_len) };
            seed_buf.copy_from_slice(s);
        }

        let kp = Ed25519KeyPair::from_seed_unchecked(&seed_buf[..])
            .map_err(|_| PqForgeError::InvalidKey("ed25519 seed rejected".into()))?;

        // SAFETY: caller buffers per contract.
        let s1 = unsafe { write_out(kp.public_key().as_ref(), pub_out, pub_cap, pub_len) };
        if s1 != PqForgeStatus::Ok {
            return Ok(s1);
        }
        // The Ed25519 secret key IS the 32-byte seed.
        let s2 = unsafe { write_out(&seed_buf[..], sec_out, sec_cap, sec_len) };
        Ok(s2)
    }))
}

/// Derives the 32-byte Ed25519 public key from a 32-byte seed. Deterministic.
///
/// # Safety
/// `seed` valid for `seed_len` reads; out/len pointers valid per cap.
#[no_mangle]
pub unsafe extern "C" fn pqforge_ed25519_public_from_seed(
    seed: *const u8,
    seed_len: usize,
    pub_out: *mut u8,
    pub_cap: usize,
    pub_len: *mut usize,
) -> c_int {
    finish(guard(|| {
        if seed.is_null() {
            return Ok(PqForgeStatus::NullArgument);
        }
        if seed_len != ED25519_SEED_LEN {
            return Ok(PqForgeStatus::InvalidKey);
        }
        // SAFETY: non-null, valid for seed_len per contract.
        let s = unsafe { slice::from_raw_parts(seed, seed_len) };
        let kp = Ed25519KeyPair::from_seed_unchecked(s)
            .map_err(|_| PqForgeError::InvalidKey("ed25519 seed rejected".into()))?;
        // SAFETY: caller buffer per contract.
        let s1 = unsafe { write_out(kp.public_key().as_ref(), pub_out, pub_cap, pub_len) };
        Ok(s1)
    }))
}

/// Signs `msg` under a 32-byte Ed25519 seed, writing the 64-byte signature.
/// Ed25519 is deterministic (RFC 8032), so the signature is byte-identical to
/// the pure-Dart provider's.
///
/// # Safety
/// `seed`/`msg` valid for their lengths (msg may be null iff msg_len == 0);
/// out/len pointers valid per cap.
#[no_mangle]
pub unsafe extern "C" fn pqforge_ed25519_sign(
    seed: *const u8,
    seed_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
    sig_cap: usize,
    sig_len: *mut usize,
) -> c_int {
    finish(guard(|| {
        if seed.is_null() || (msg.is_null() && msg_len != 0) {
            return Ok(PqForgeStatus::NullArgument);
        }
        if seed_len != ED25519_SEED_LEN {
            return Ok(PqForgeStatus::InvalidKey);
        }
        // SAFETY: non-null/length-checked per contract.
        let s = unsafe { slice::from_raw_parts(seed, seed_len) };
        let msg_slice = if msg_len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(msg, msg_len) }
        };

        let kp = Ed25519KeyPair::from_seed_unchecked(s)
            .map_err(|_| PqForgeError::InvalidKey("ed25519 seed rejected".into()))?;
        let sig = kp.sign(msg_slice);

        // SAFETY: caller buffer per contract.
        let s1 = unsafe { write_out(sig.as_ref(), sig_out, sig_cap, sig_len) };
        Ok(s1)
    }))
}

/// Verifies a 64-byte Ed25519 signature over `msg` under a 32-byte public key.
/// Returns `Ok` (0) if valid, `AuthFailed` (3) for an invalid signature *or* a
/// wrong-length key/signature (a malformed input simply does not verify),
/// `NullArgument` (10) for a null pointer.
///
/// # Safety
/// `pubkey`/`msg`/`sig` valid for their lengths (msg may be null iff msg_len==0).
#[no_mangle]
pub unsafe extern "C" fn pqforge_ed25519_verify(
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
        // A wrong-length key or signature can never verify.
        if pubkey_len != ED25519_PUBLIC_LEN || sig_len != ED25519_SIGNATURE_LEN {
            return Ok(PqForgeStatus::AuthFailed);
        }
        // SAFETY: non-null/length-checked per contract.
        let pub_slice = unsafe { slice::from_raw_parts(pubkey, pubkey_len) };
        let sig_slice = unsafe { slice::from_raw_parts(sig, sig_len) };
        let msg_slice = if msg_len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(msg, msg_len) }
        };

        let verified = UnparsedPublicKey::new(&ED25519, pub_slice).verify(msg_slice, sig_slice);
        Ok(if verified.is_ok() {
            PqForgeStatus::Ok
        } else {
            PqForgeStatus::AuthFailed
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x25519_keygen(seed: Option<&[u8]>) -> (Vec<u8>, Vec<u8>) {
        let mut pk = vec![0u8; X25519_KEY_LEN + 16];
        let mut sk = vec![0u8; X25519_KEY_LEN + 16];
        let (mut pl, mut sl) = (0usize, 0usize);
        let (sptr, slen) = match seed {
            Some(s) => (s.as_ptr(), s.len()),
            None => (std::ptr::null(), 0),
        };
        let rc = unsafe {
            pqforge_x25519_keygen(
                sptr,
                slen,
                pk.as_mut_ptr(),
                pk.len(),
                &mut pl,
                sk.as_mut_ptr(),
                sk.len(),
                &mut sl,
            )
        };
        assert_eq!(rc, PqForgeStatus::Ok.code());
        assert_eq!((pl, sl), (X25519_KEY_LEN, X25519_KEY_LEN));
        pk.truncate(pl);
        sk.truncate(sl);
        (pk, sk)
    }

    fn x25519_ecdh(secret: &[u8], peer_pub: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; X25519_KEY_LEN + 16];
        let mut ol = 0usize;
        let rc = unsafe {
            pqforge_x25519_ecdh(
                secret.as_ptr(),
                secret.len(),
                peer_pub.as_ptr(),
                peer_pub.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut ol,
            )
        };
        assert_eq!(rc, PqForgeStatus::Ok.code());
        out.truncate(ol);
        out
    }

    #[test]
    fn x25519_ecdh_is_symmetric() {
        let (pk_a, sk_a) = x25519_keygen(None);
        let (pk_b, sk_b) = x25519_keygen(None);
        let ss_ab = x25519_ecdh(&sk_a, &pk_b);
        let ss_ba = x25519_ecdh(&sk_b, &pk_a);
        assert_eq!(ss_ab, ss_ba, "X25519 ECDH must be symmetric");
        assert_eq!(ss_ab.len(), X25519_KEY_LEN);
    }

    #[test]
    fn x25519_seeded_keygen_is_deterministic() {
        let seed = [7u8; X25519_KEY_LEN];
        let (pk1, sk1) = x25519_keygen(Some(&seed));
        let (pk2, sk2) = x25519_keygen(Some(&seed));
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
        assert_eq!(sk1, seed.to_vec(), "the X25519 secret key is its own seed");
        let (pk3, _) = x25519_keygen(Some(&[9u8; X25519_KEY_LEN]));
        assert_ne!(pk1, pk3, "different seed → different key");
    }

    #[test]
    fn x25519_wrong_seed_length_is_invalid_key() {
        let mut pk = vec![0u8; 64];
        let mut sk = vec![0u8; 64];
        let (mut pl, mut sl) = (0usize, 0usize);
        let short = [0u8; 31];
        let rc = unsafe {
            pqforge_x25519_keygen(
                short.as_ptr(),
                short.len(),
                pk.as_mut_ptr(),
                pk.len(),
                &mut pl,
                sk.as_mut_ptr(),
                sk.len(),
                &mut sl,
            )
        };
        assert_eq!(rc, PqForgeStatus::InvalidKey.code());
    }

    fn ed25519_keygen(seed: Option<&[u8]>) -> (Vec<u8>, Vec<u8>) {
        let mut pk = vec![0u8; ED25519_PUBLIC_LEN + 16];
        let mut sk = vec![0u8; ED25519_SEED_LEN + 16];
        let (mut pl, mut sl) = (0usize, 0usize);
        let (sptr, slen) = match seed {
            Some(s) => (s.as_ptr(), s.len()),
            None => (std::ptr::null(), 0),
        };
        let rc = unsafe {
            pqforge_ed25519_keygen(
                sptr,
                slen,
                pk.as_mut_ptr(),
                pk.len(),
                &mut pl,
                sk.as_mut_ptr(),
                sk.len(),
                &mut sl,
            )
        };
        assert_eq!(rc, PqForgeStatus::Ok.code());
        assert_eq!((pl, sl), (ED25519_PUBLIC_LEN, ED25519_SEED_LEN));
        pk.truncate(pl);
        sk.truncate(sl);
        (pk, sk)
    }

    fn ed25519_sign(seed: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut sig = vec![0u8; ED25519_SIGNATURE_LEN + 16];
        let mut sigl = 0usize;
        let rc = unsafe {
            pqforge_ed25519_sign(
                seed.as_ptr(),
                seed.len(),
                msg.as_ptr(),
                msg.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut sigl,
            )
        };
        assert_eq!(rc, PqForgeStatus::Ok.code());
        sig.truncate(sigl);
        sig
    }

    fn ed25519_verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> i32 {
        unsafe {
            pqforge_ed25519_verify(
                pubkey.as_ptr(),
                pubkey.len(),
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
                sig.len(),
            )
        }
    }

    #[test]
    fn ed25519_sign_verify_round_trip() {
        let (pk, sk) = ed25519_keygen(None);
        let msg = b"pqforge Ed25519 self-test";
        let sig = ed25519_sign(&sk, msg);
        assert_eq!(sig.len(), ED25519_SIGNATURE_LEN);
        assert_eq!(ed25519_verify(&pk, msg, &sig), PqForgeStatus::Ok.code());
    }

    #[test]
    fn ed25519_verify_rejects_tamper() {
        let (pk, sk) = ed25519_keygen(None);
        let sig = ed25519_sign(&sk, b"original");
        assert_eq!(
            ed25519_verify(&pk, b"tampered", &sig),
            PqForgeStatus::AuthFailed.code()
        );
        // Wrong-length key/sig also fail (not verify).
        assert_eq!(
            ed25519_verify(&pk[..31], b"original", &sig),
            PqForgeStatus::AuthFailed.code()
        );
    }

    #[test]
    fn ed25519_seeded_keygen_deterministic_and_public_from_seed_matches() {
        let seed = [3u8; ED25519_SEED_LEN];
        let (pk1, sk1) = ed25519_keygen(Some(&seed));
        let (pk2, _) = ed25519_keygen(Some(&seed));
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, seed.to_vec(), "the Ed25519 secret key is its own seed");

        let mut pk = vec![0u8; ED25519_PUBLIC_LEN + 16];
        let mut pl = 0usize;
        let rc = unsafe {
            pqforge_ed25519_public_from_seed(
                seed.as_ptr(),
                seed.len(),
                pk.as_mut_ptr(),
                pk.len(),
                &mut pl,
            )
        };
        assert_eq!(rc, PqForgeStatus::Ok.code());
        pk.truncate(pl);
        assert_eq!(pk, pk1, "public_from_seed must match keygen's public key");
    }
}
