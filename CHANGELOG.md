# Changelog

## 0.1.1

### Added

- `NativePqforgeClassicalProvider` implements the four NIST-curve ECDH methods
  `PqClassicalProvider` gained in pqforge 0.4 — `p256GenerateKeyPair`,
  `p256SharedSecret`, `p384GenerateKeyPair`, `p384SharedSecret`. They delegate
  to `fallback`, exactly as ECDSA-P256 already did.

### Changed

- `pqforge` constraint widened from `^0.3.0` to `^0.4.6`, which also moves
  `pqcrypto` from 0.3.1 to 0.4.2.

### Why

This package was pinned two major versions behind and could not move. Against
pqforge 0.4.x it did not compile at all:

```
Error: The non-abstract class 'NativePqforgeClassicalProvider' is missing
implementations for these members:
  p256GenerateKeyPair, p256SharedSecret, p384GenerateKeyPair, p384SharedSecret
```

Because `pqforge` was pinned rather than merely stale, the failure was invisible
until someone widened the constraint — which is why it sat there.

Delegating to `fallback` is the honest option. aws-lc-rs does expose NIST ECDH,
but this package does not bind it; adding a binding later needs no change to
this class's contract. P-256/P-384 ECDH is therefore correct but not
accelerated. X25519 and Ed25519 — the hybrid defaults — remain fully native.

Also worth recording: `pana` scored this 150/160 with the whole gap being "all
dependencies are supported in the latest version", because `pqforge: ^0.3.0`
while 0.4.6 was published. Pinning a dependency is a way of silently opting out
of both the points and the updates.

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
