//! Native zero-FFI file streaming (blueprint §8.4).
//!
//! Seals/opens a file directly in Rust using the **same STREAM construction** as
//! the Dart `PqForgeStream` (per-frame nonce = big-endian counter ‖ last-flag,
//! held-back-last framing), so a file produced here opens with the Dart layer and
//! vice-versa. Sequential buffered I/O keeps memory bounded regardless of file
//! size; the per-stream key is held in a [`PinnedSecret`] (mlock + zeroize).
//!
//! rayon-parallel AEAD + O_DIRECT (blueprint §8.4 "max throughput") is a later
//! optimization; this provides the correct, zero-per-chunk-FFI capability.

use std::ffi::CStr;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::raw::{c_char, c_int};
use std::path::PathBuf;
use std::slice;

use aws_lc_rs::aead::{
    Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305,
};
use zeroize::Zeroizing;

use crate::error::{finish, guard, PqForgeError, PqForgeStatus, PqResult};
use crate::secret::PinnedSecret;

const TAG_LEN: usize = 16;
const IO_BUF: usize = 1 << 16; // 64 KiB I/O buffer

fn aead_alg(id: c_int) -> Option<&'static Algorithm> {
    match id {
        0 => Some(&AES_256_GCM),
        1 => Some(&CHACHA20_POLY1305),
        _ => None,
    }
}

/// STREAM nonce: big-endian counter in bytes [0..11], last-flag in byte 11.
/// Byte-identical to the Dart `PqForgeStream` nonce.
fn stream_nonce(counter: u64, last: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[3..11].copy_from_slice(&counter.to_be_bytes());
    nonce[11] = u8::from(last);
    nonce
}

fn io_err(e: std::io::Error) -> PqForgeError {
    PqForgeError::Io(e.to_string())
}

/// # Safety
/// `ptr` must be a valid NUL-terminated C string.
unsafe fn cstr_path(ptr: *const c_char) -> PqResult<PathBuf> {
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| PqForgeError::Io("path is not valid UTF-8".into()))?;
    Ok(PathBuf::from(s))
}

/// Reads up to `size` bytes into a fresh buffer; returns `None` at immediate EOF.
fn read_block<R: Read>(reader: &mut R, size: usize) -> PqResult<Option<Vec<u8>>> {
    let mut buf = vec![0u8; size];
    let mut total = 0;
    while total < size {
        let n = reader.read(&mut buf[total..]).map_err(io_err)?;
        if n == 0 {
            break;
        }
        total += n;
    }
    if total == 0 {
        Ok(None)
    } else {
        buf.truncate(total);
        Ok(Some(buf))
    }
}

/// Seals `in_path` into `out_path` as a STREAM of `chunk_size`-plaintext frames.
///
/// # Safety
/// `key`/`aad` valid for their lengths (or null with len 0); `in_path`/`out_path`
/// valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn pqforge_stream_seal_file(
    alg_id: c_int,
    key: *const u8,
    key_len: usize,
    aad: *const u8,
    aad_len: usize,
    chunk_size: usize,
    in_path: *const c_char,
    out_path: *const c_char,
) -> c_int {
    finish(guard(|| {
        let algorithm = match aead_alg(alg_id) {
            Some(a) => a,
            None => return Ok(PqForgeStatus::InvalidKey),
        };
        if key.is_null()
            || in_path.is_null()
            || out_path.is_null()
            || (aad.is_null() && aad_len != 0)
        {
            return Ok(PqForgeStatus::NullArgument);
        }
        if chunk_size == 0 {
            return Ok(PqForgeStatus::Unaligned);
        }
        // SAFETY: pointers validated above.
        let secret = PinnedSecret::from_slice(unsafe { slice::from_raw_parts(key, key_len) })?;
        let ad = read_aad(aad, aad_len);
        let in_path = unsafe { cstr_path(in_path) }?;
        let out_path = unsafe { cstr_path(out_path) }?;

        let sealing = match UnboundKey::new(algorithm, secret.as_slice()) {
            Ok(u) => LessSafeKey::new(u),
            Err(_) => return Ok(PqForgeStatus::InvalidKey),
        };

        let mut reader = BufReader::with_capacity(IO_BUF, File::open(&in_path).map_err(io_err)?);
        let mut writer = BufWriter::with_capacity(IO_BUF, File::create(&out_path).map_err(io_err)?);

        let mut counter: u64 = 0;
        let mut held = read_block(&mut reader, chunk_size)?;
        if held.is_none() {
            // Empty input → a single empty final frame.
            seal_frame(&mut writer, &sealing, &[], counter, true, &ad)?;
        } else {
            loop {
                let chunk = held.take().expect("held is Some in this branch");
                let next = read_block(&mut reader, chunk_size)?;
                let last = next.is_none();
                seal_frame(&mut writer, &sealing, &chunk, counter, last, &ad)?;
                counter = next_counter(counter)?;
                if last {
                    break;
                }
                held = next;
            }
        }
        writer.flush().map_err(io_err)?;
        Ok(PqForgeStatus::Ok)
    }))
}

/// Opens `in_path` into `out_path`. Returns `AuthFailed` on any tamper / reorder /
/// truncation / extension, `InvalidCiphertext` on a malformed stream.
///
/// On a non-`Ok` return the output file is partial and must be discarded by the
/// caller (the Dart wrapper does this atomically via a temp file + rename).
///
/// # Safety
/// As for [`pqforge_stream_seal_file`].
#[no_mangle]
pub unsafe extern "C" fn pqforge_stream_open_file(
    alg_id: c_int,
    key: *const u8,
    key_len: usize,
    aad: *const u8,
    aad_len: usize,
    chunk_size: usize,
    in_path: *const c_char,
    out_path: *const c_char,
) -> c_int {
    finish(guard(|| {
        let algorithm = match aead_alg(alg_id) {
            Some(a) => a,
            None => return Ok(PqForgeStatus::InvalidKey),
        };
        if key.is_null()
            || in_path.is_null()
            || out_path.is_null()
            || (aad.is_null() && aad_len != 0)
        {
            return Ok(PqForgeStatus::NullArgument);
        }
        if chunk_size == 0 {
            return Ok(PqForgeStatus::Unaligned);
        }
        let secret = PinnedSecret::from_slice(unsafe { slice::from_raw_parts(key, key_len) })?;
        let ad = read_aad(aad, aad_len);
        let in_path = unsafe { cstr_path(in_path) }?;
        let out_path = unsafe { cstr_path(out_path) }?;

        let opening = match UnboundKey::new(algorithm, secret.as_slice()) {
            Ok(u) => LessSafeKey::new(u),
            Err(_) => return Ok(PqForgeStatus::InvalidKey),
        };

        let cipher_chunk = chunk_size + TAG_LEN;
        let mut reader = BufReader::with_capacity(IO_BUF, File::open(&in_path).map_err(io_err)?);
        let mut writer = BufWriter::with_capacity(IO_BUF, File::create(&out_path).map_err(io_err)?);

        let mut counter: u64 = 0;
        let mut held = read_block(&mut reader, cipher_chunk)?;
        if held.is_none() {
            return Ok(PqForgeStatus::InvalidCiphertext); // empty stream
        }
        loop {
            let frame = held.take().expect("held is Some in this loop");
            if frame.len() < TAG_LEN {
                return Ok(PqForgeStatus::InvalidCiphertext);
            }
            let next = read_block(&mut reader, cipher_chunk)?;
            // A frame is the last iff it is short (EOF reached) or nothing follows.
            let last = frame.len() < cipher_chunk || next.is_none();
            match open_frame(&mut writer, &opening, &frame, counter, last, &ad) {
                Ok(()) => {}
                Err(PqForgeError::AuthFailed) => return Ok(PqForgeStatus::AuthFailed),
                Err(e) => return Err(e),
            }
            counter = next_counter(counter)?;
            if last {
                if next.is_some() {
                    return Ok(PqForgeStatus::InvalidCiphertext); // data after final frame
                }
                break;
            }
            held = next;
        }
        writer.flush().map_err(io_err)?;
        Ok(PqForgeStatus::Ok)
    }))
}

fn read_aad(aad: *const u8, aad_len: usize) -> Vec<u8> {
    if aad_len == 0 || aad.is_null() {
        Vec::new()
    } else {
        // SAFETY: aad non-null and valid for aad_len per the caller contract.
        unsafe { slice::from_raw_parts(aad, aad_len) }.to_vec()
    }
}

fn next_counter(counter: u64) -> PqResult<u64> {
    counter
        .checked_add(1)
        .ok_or_else(|| PqForgeError::Internal("frame counter overflow".into()))
}

fn seal_frame<W: Write>(
    writer: &mut W,
    key: &LessSafeKey,
    chunk: &[u8],
    counter: u64,
    last: bool,
    aad: &[u8],
) -> PqResult<()> {
    let nonce = Nonce::try_assume_unique_for_key(&stream_nonce(counter, last))
        .map_err(|_| PqForgeError::Internal("nonce".into()))?;
    let mut buf = chunk.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut buf)
        .map_err(|_| PqForgeError::Internal("AEAD seal failed".into()))?;
    writer.write_all(&buf).map_err(io_err)
}

fn open_frame<W: Write>(
    writer: &mut W,
    key: &LessSafeKey,
    frame: &[u8],
    counter: u64,
    last: bool,
    aad: &[u8],
) -> PqResult<()> {
    let nonce = Nonce::try_assume_unique_for_key(&stream_nonce(counter, last))
        .map_err(|_| PqForgeError::Internal("nonce".into()))?;
    let mut buf = Zeroizing::new(frame.to_vec());
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad), buf.as_mut_slice())
        .map_err(|_| PqForgeError::AuthFailed)?;
    writer.write_all(plaintext).map_err(io_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::Write;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("pqforge_sf_{}_{}", std::process::id(), name));
        p
    }

    fn seal(alg: c_int, key: &[u8], chunk: usize, input: &PathBuf, output: &PathBuf) -> c_int {
        let i = CString::new(input.to_str().unwrap()).unwrap();
        let o = CString::new(output.to_str().unwrap()).unwrap();
        unsafe {
            pqforge_stream_seal_file(
                alg,
                key.as_ptr(),
                key.len(),
                std::ptr::null(),
                0,
                chunk,
                i.as_ptr(),
                o.as_ptr(),
            )
        }
    }

    fn open(alg: c_int, key: &[u8], chunk: usize, input: &PathBuf, output: &PathBuf) -> c_int {
        let i = CString::new(input.to_str().unwrap()).unwrap();
        let o = CString::new(output.to_str().unwrap()).unwrap();
        unsafe {
            pqforge_stream_open_file(
                alg,
                key.as_ptr(),
                key.len(),
                std::ptr::null(),
                0,
                chunk,
                i.as_ptr(),
                o.as_ptr(),
            )
        }
    }

    #[test]
    fn seal_open_file_round_trip_various_sizes() {
        let key = [5u8; 32];
        let chunk = 64usize;
        for &size in &[0usize, 1, 63, 64, 65, 200, 4096] {
            let plain: Vec<u8> = (0..size).map(|i| (i * 31 + 7) as u8).collect();
            let pin = tmp(&format!("in_{size}"));
            let enc = tmp(&format!("enc_{size}"));
            let dec = tmp(&format!("dec_{size}"));
            File::create(&pin).unwrap().write_all(&plain).unwrap();

            assert_eq!(seal(0, &key, chunk, &pin, &enc), PqForgeStatus::Ok.code());
            assert_eq!(open(0, &key, chunk, &enc, &dec), PqForgeStatus::Ok.code());

            let mut out = Vec::new();
            File::open(&dec).unwrap().read_to_end(&mut out).unwrap();
            assert_eq!(out, plain, "round-trip failed for size {size}");

            for p in [pin, enc, dec] {
                let _ = std::fs::remove_file(p);
            }
        }
    }

    #[test]
    fn tampered_file_fails_authentication() {
        let key = [6u8; 32];
        let pin = tmp("tamper_in");
        let enc = tmp("tamper_enc");
        let dec = tmp("tamper_dec");
        File::create(&pin).unwrap().write_all(&[9u8; 300]).unwrap();
        assert_eq!(seal(1, &key, 64, &pin, &enc), PqForgeStatus::Ok.code());

        // flip a byte in the encrypted file
        let mut data = Vec::new();
        File::open(&enc).unwrap().read_to_end(&mut data).unwrap();
        data[5] ^= 0xFF;
        File::create(&enc).unwrap().write_all(&data).unwrap();

        assert_eq!(
            open(1, &key, 64, &enc, &dec),
            PqForgeStatus::AuthFailed.code()
        );
        for p in [pin, enc, dec] {
            let _ = std::fs::remove_file(p);
        }
    }
}
