//! Typed error taxonomy + the FFI panic boundary.
//!
//! The integer values of [`PqForgeStatus`] mirror Dart's `PqForgeErrorCode`
//! exactly — they are the ABI; do not renumber. A panic must never unwind across
//! an `extern "C"` boundary (that is undefined behaviour), so [`guard`] converts
//! any panic into [`PqForgeError::Internal`].

use std::panic::{catch_unwind, AssertUnwindSafe};

/// Stable status codes shared with the Dart side. `#[repr(i32)]` makes the
/// integer value the ABI.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqForgeStatus {
    Ok = 0,
    InvalidKey = 1,
    InvalidCiphertext = 2,
    AuthFailed = 3,
    Unaligned = 4,
    Io = 5,
    Device = 6,
    Anchor = 7,
    Unsupported = 8,
    Internal = 9,
    NullArgument = 10,
    BufferTooSmall = 11,
}

impl PqForgeStatus {
    pub fn code(self) -> i32 {
        self as i32
    }

    /// Maps a raw code back to a status; unknown codes fold to [`Self::Internal`]
    /// (an unrecognized failure is still a failure).
    pub fn from_code(code: i32) -> PqForgeStatus {
        match code {
            0 => Self::Ok,
            1 => Self::InvalidKey,
            2 => Self::InvalidCiphertext,
            3 => Self::AuthFailed,
            4 => Self::Unaligned,
            5 => Self::Io,
            6 => Self::Device,
            7 => Self::Anchor,
            8 => Self::Unsupported,
            10 => Self::NullArgument,
            11 => Self::BufferTooSmall,
            _ => Self::Internal,
        }
    }

    /// Stable lower-snake name, used by `pqforge_status_message` to prove the
    /// taxonomy round-trips across the FFI boundary.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::InvalidKey => "invalid_key",
            Self::InvalidCiphertext => "invalid_ciphertext",
            Self::AuthFailed => "auth_failed",
            Self::Unaligned => "unaligned",
            Self::Io => "io",
            Self::Device => "device",
            Self::Anchor => "anchor",
            Self::Unsupported => "unsupported",
            Self::Internal => "internal",
            Self::NullArgument => "null_argument",
            Self::BufferTooSmall => "buffer_too_small",
        }
    }
}

/// Rich internal error. Maps to a [`PqForgeStatus`] at the FFI boundary.
#[derive(Debug)]
pub enum PqForgeError {
    InvalidKey(String),
    InvalidCiphertext,
    AuthFailed,
    Unsupported(String),
    Internal(String),
}

impl PqForgeError {
    pub fn status(&self) -> PqForgeStatus {
        match self {
            Self::InvalidKey(_) => PqForgeStatus::InvalidKey,
            Self::InvalidCiphertext => PqForgeStatus::InvalidCiphertext,
            Self::AuthFailed => PqForgeStatus::AuthFailed,
            Self::Unsupported(_) => PqForgeStatus::Unsupported,
            Self::Internal(_) => PqForgeStatus::Internal,
        }
    }
}

pub type PqResult<T> = Result<T, PqForgeError>;

/// Runs `f`, catching any panic and converting it to [`PqForgeError::Internal`]
/// so a panic can never unwind across the FFI boundary.
pub fn guard<T>(f: impl FnOnce() -> PqResult<T>) -> PqResult<T> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_string());
            Err(PqForgeError::Internal(msg))
        }
    }
}

/// Writes `src` into the caller buffer `(out, cap)`, always setting `*len` to
/// the required length so a caller can retry after [`PqForgeStatus::BufferTooSmall`].
///
/// # Safety
/// `out` must be valid for `cap` writes (or null); `len` a valid `*mut usize`
/// (or null).
pub unsafe fn write_out(
    src: &[u8],
    out: *mut u8,
    cap: usize,
    len: *mut usize,
) -> PqForgeStatus {
    if len.is_null() {
        return PqForgeStatus::NullArgument;
    }
    // SAFETY: len checked non-null directly above.
    unsafe { *len = src.len() };
    if out.is_null() {
        return PqForgeStatus::NullArgument;
    }
    if cap < src.len() {
        return PqForgeStatus::BufferTooSmall;
    }
    // SAFETY: out non-null with cap >= src.len() writable bytes.
    let dst = unsafe { std::slice::from_raw_parts_mut(out, src.len()) };
    dst.copy_from_slice(src);
    PqForgeStatus::Ok
}

/// Reduces a guarded result to a C status code: an explicit error maps to its
/// status, a caught panic (guard `Err`) to `Internal`.
pub fn finish(result: PqResult<PqForgeStatus>) -> i32 {
    match result {
        Ok(status) => status.code(),
        Err(error) => error.status().code(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defined_status_codes_round_trip() {
        for code in 0..=11 {
            assert_eq!(PqForgeStatus::from_code(code).code(), code);
        }
    }

    #[test]
    fn unknown_codes_fold_to_internal() {
        assert_eq!(PqForgeStatus::from_code(999), PqForgeStatus::Internal);
        assert_eq!(PqForgeStatus::from_code(-1), PqForgeStatus::Internal);
    }

    #[test]
    fn guard_converts_panic_to_internal() {
        let r: PqResult<()> = guard(|| panic!("boom"));
        match r {
            Err(PqForgeError::Internal(m)) => assert!(m.contains("boom")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn guard_passes_ok_through() {
        assert_eq!(guard(|| Ok::<_, PqForgeError>(42)).unwrap(), 42);
    }

    #[test]
    fn errors_map_to_status() {
        assert_eq!(
            PqForgeError::InvalidCiphertext.status(),
            PqForgeStatus::InvalidCiphertext
        );
        assert_eq!(PqForgeError::AuthFailed.status(), PqForgeStatus::AuthFailed);
        assert_eq!(
            PqForgeError::InvalidKey("x".into()).status(),
            PqForgeStatus::InvalidKey
        );
    }
}
