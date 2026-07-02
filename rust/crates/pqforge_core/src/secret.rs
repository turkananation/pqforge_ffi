//! Process-pinned, zeroize-on-drop secret buffer.
//!
//! Wraps key material that is resident in Rust for the duration of an operation
//! (e.g. the per-stream key of the native file pipeline): `mlock` keeps it out of
//! swap, and it is wiped on drop. mlock is best-effort — if `RLIMIT_MEMLOCK`
//! forbids it for an unprivileged process, the zeroize-on-drop guarantee still
//! holds.

use zeroize::Zeroize;

use crate::error::PqResult;

pub struct PinnedSecret {
    bytes: Vec<u8>,
    locked: bool,
}

impl PinnedSecret {
    /// Copies `src` into a pinned, zeroize-on-drop buffer.
    pub fn from_slice(src: &[u8]) -> PqResult<Self> {
        let mut bytes = vec![0u8; src.len()];
        bytes.copy_from_slice(src);
        let mut secret = Self {
            bytes,
            locked: false,
        };
        secret.lock();
        Ok(secret)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    #[cfg(unix)]
    fn lock(&mut self) {
        if self.bytes.is_empty() {
            return;
        }
        // SAFETY: ptr/len describe a live, owned allocation.
        let ret = unsafe { libc::mlock(self.bytes.as_ptr().cast(), self.bytes.len()) };
        self.locked = ret == 0;
    }

    #[cfg(not(unix))]
    fn lock(&mut self) {
        // TODO: VirtualLock on Windows (needs windows-sys). Zeroize-on-drop holds.
    }
}

impl Drop for PinnedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(unix)]
        if self.locked {
            // SAFETY: ptr/len describe the allocation locked in `lock`.
            unsafe {
                let _ = libc::munlock(self.bytes.as_ptr().cast(), self.bytes.len());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_and_exposes_bytes() {
        let secret = PinnedSecret::from_slice(&[1, 2, 3, 4]).unwrap();
        assert_eq!(secret.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn empty_secret_is_fine() {
        let secret = PinnedSecret::from_slice(&[]).unwrap();
        assert!(secret.as_slice().is_empty());
    }
}
