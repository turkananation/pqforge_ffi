# Changelog

## Unreleased

- Relicensed to MIT. Dual AGPL-3.0-only / commercial licensing is dropped;
  `COMMERCIAL-LICENSE.md` is removed.

## 0.1.0

Initial release.

- Native AWS-LC engine (`pqforge_core` Rust cdylib over `aws-lc-rs`) with a
  panic-guarded C ABI, ABI-version handshake, and AWS-LC self-test validation
  at load time.
- Drop-in acceleration for the whole `pqforge` toolkit through its provider
  seams: `PqLattice.provider` (ML-KEM 512/768/1024, ML-DSA 44/65/87) and
  `PqClassical.provider` (X25519, Ed25519).
- Standalone accelerated primitives via the `PqForge` facade: KEM, signatures,
  AEAD (AES-256-GCM, ChaCha20-Poly1305), single-shot KEM-DEM envelopes, and a
  streaming STREAM pipeline for TB-scale data.
- Native file cipher (`PqForgeFileCipher`): seal/open entire files in native
  code with zero per-chunk FFI, atomic temp+rename output, `mlock`ed and
  zeroized key handling.
- Byte-compatible pure-Dart fallback (`pqforge` itself): every entry point
  degrades silently to pure Dart when the native library is absent or fails
  validation; deterministic operations are proven byte-identical by
  cross-implementation known-answer and agreement tests.
