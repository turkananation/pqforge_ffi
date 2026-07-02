//! pqforge_core — native FFI core for the `pqforge_ffi` Dart package.
//!
//! **Phase 1b: the C-ABI spine.** This exposes the ABI probe, the shared
//! status-code taxonomy, and a panic-guarded error round-trip — enough to
//! validate the `dart:ffi` boundary end-to-end *before* any cryptography is
//! wired (Phase 2). The validation bar is deliberately not "it links": the
//! tests prove typed errors and a recovered panic round-trip correctly.

mod crypto;
mod error;
mod secret;

pub use error::{guard, PqForgeError, PqForgeStatus, PqResult};

use std::os::raw::c_int;
use std::slice;

/// ABI version of this C surface. Must equal Dart's `kPqForgeAbiVersion`.
#[no_mangle]
pub extern "C" fn pqforge_abi_version() -> u32 {
    1
}

/// Round-trips a status code through the shared taxonomy: returns the same code
/// for any known status, or `Internal` (9) for an unknown one. Proves the Dart
/// and Rust error enums agree across the boundary.
#[no_mangle]
pub extern "C" fn pqforge_status_echo(code: c_int) -> c_int {
    PqForgeStatus::from_code(code as i32).code() as c_int
}

/// Self-test: deliberately panics inside [`guard`]. MUST return `Internal` (9)
/// and never abort the process — live proof that a Rust panic cannot cross the
/// FFI boundary.
#[no_mangle]
pub extern "C" fn pqforge_selftest_panic() -> c_int {
    // Silence the default panic hook for this *intentional* panic so it does not
    // pollute logs, then restore it. Real panics keep their normal reporting.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r: PqResult<c_int> = guard(|| panic!("intentional pqforge self-test panic"));
    std::panic::set_hook(previous);
    match r {
        Ok(v) => v,
        Err(e) => e.status().code() as c_int,
    }
}

/// Writes the lower-snake name of `code` into the caller buffer (not
/// NUL-terminated; the true length is returned via `out_len`).
///
/// Returns `Ok` (0) on success; `BufferTooSmall` (11) if `out_cap` is too small
/// (with `*out_len` set to the required length so the caller can retry);
/// `NullArgument` (10) if a required pointer is null; `Internal` (9) if a panic
/// was caught. No panic can escape.
///
/// # Safety
/// `out` must point to at least `out_cap` writable bytes (or be null), and
/// `out_len` must be a valid `*mut usize` (or null).
#[no_mangle]
pub unsafe extern "C" fn pqforge_status_message(
    code: c_int,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    let status = guard(|| {
        let name = PqForgeStatus::from_code(code as i32).name();
        let bytes = name.as_bytes();
        if out_len.is_null() {
            return Ok(PqForgeStatus::NullArgument);
        }
        // SAFETY: out_len checked non-null directly above.
        unsafe { *out_len = bytes.len() };
        if out.is_null() {
            return Ok(PqForgeStatus::NullArgument);
        }
        if out_cap < bytes.len() {
            return Ok(PqForgeStatus::BufferTooSmall);
        }
        // SAFETY: out is non-null with at least out_cap >= bytes.len() bytes.
        let dst = unsafe { slice::from_raw_parts_mut(out, bytes.len()) };
        dst.copy_from_slice(bytes);
        Ok(PqForgeStatus::Ok)
    })
    .unwrap_or(PqForgeStatus::Internal);
    status.code() as c_int
}

#[cfg(test)]
mod ffi_tests {
    use super::*;

    #[test]
    fn abi_version_is_one() {
        assert_eq!(pqforge_abi_version(), 1);
    }

    #[test]
    fn status_echo_round_trips_and_folds_unknown() {
        assert_eq!(pqforge_status_echo(2), 2);
        assert_eq!(pqforge_status_echo(11), 11);
        assert_eq!(pqforge_status_echo(999), PqForgeStatus::Internal.code());
    }

    #[test]
    fn selftest_panic_returns_internal_not_abort() {
        assert_eq!(pqforge_selftest_panic(), PqForgeStatus::Internal.code());
    }

    #[test]
    fn status_message_writes_name() {
        let mut buf = [0u8; 64];
        let mut len: usize = 0;
        let rc = unsafe {
            pqforge_status_message(1, buf.as_mut_ptr(), buf.len(), &mut len)
        };
        assert_eq!(rc, PqForgeStatus::Ok.code());
        assert_eq!(&buf[..len], b"invalid_key");
    }

    #[test]
    fn status_message_reports_buffer_too_small() {
        let mut buf = [0u8; 2];
        let mut len: usize = 0;
        let rc = unsafe {
            pqforge_status_message(1, buf.as_mut_ptr(), buf.len(), &mut len)
        };
        assert_eq!(rc, PqForgeStatus::BufferTooSmall.code());
        assert_eq!(len, "invalid_key".len());
    }

    #[test]
    fn status_message_rejects_null_out_len() {
        let mut buf = [0u8; 64];
        let rc = unsafe {
            pqforge_status_message(1, buf.as_mut_ptr(), buf.len(), std::ptr::null_mut())
        };
        assert_eq!(rc, PqForgeStatus::NullArgument.code());
    }
}
