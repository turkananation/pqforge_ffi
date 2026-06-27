# pqforge_ffi — Implementation Roadmap

> Companion to [`ARCHITECTURE_BLUEPRINT.md`](ARCHITECTURE_BLUEPRINT.md) (the spec/contract)
> and [`MILESTONE_TRACKERS.md`](MILESTONE_TRACKERS.md) (the checkboxes). Section references
> like `§5.3` or `§11-O1` point into the blueprint. Mark progress in the trackers doc as each
> Definition-of-Done is met.

## Phased roadmap

Each phase has a **Definition of Done (DoD)** and the **live API risk** to verify before
writing the code (per the no-hallucination rule).

### Phase 1 — Foundation & fallback

- Cargo workspace + Dart package build side-by-side.
- `PqForgeError` taxonomy; every Rust failure crosses FFI as a typed Dart exception; no
  panic ever unwinds across the boundary.
- `PqForgeBackend` contract; pure-Dart fallback wired to `pqforge`.
- Runtime selector probes for the native lib and logs the chosen path.
- **DoD:** `dart test` green on the pure-Dart path with **no native lib present**.
- **Live risk:** Native Assets `hooks`/`code_assets` surface (verified, §5.3); FRB v2 loader
  ↔ native-asset handshake (§11-O1).

### Phase 2 — Rust crypto core

- ML-KEM-768/1024 encapsulate/decapsulate via AWS-LC.
- ML-DSA-65/87 sign/verify (AWS-LC if exposed; else `fips204`), behind one trait.
- `Zeroizing`/`ZeroizeOnDrop` on every key, shared secret, and scratch buffer.
- `mlock`/`VirtualLock` pinning + core-dump/hibernation guards.
- **DoD:** ML-KEM & ML-DSA match FIPS 203/204 KAT vectors; secrets verified zeroed under a
  debugger/valgrind; no secret reaches swap (manual `mlock` audit).
- **Live risk:** `aws-lc-rs` ML-DSA public API (§11-O2); `unstable` feature gating for KEM.

### Phase 3 — Streaming & archive (functional baseline)

- Zstd → tar → AEAD streaming pipeline (functional baseline; the final STREAM framing and
  TB-scale throughput are hardened in Phase 3.5).
- `memmap2` zero-copy path for large directories with a chunked-streaming fallback.
- Progress events surfaced as a Dart `Stream` via FRB `StreamSink`.
- **DoD:** 10 GB pack/unpack round-trips bit-exact under bounded RAM (< 128 MB RSS).
- **Live risk:** AEAD nonce strategy — finalized as the STREAM construction in Phase 3.5.

### Phase 3.5 — TB-scale data path & dual-profile engine

- **Dual-profile cipher suite** (caller-selectable): `FipsStrict` (AES-256-GCM + ECDH P-256 +
  ML-KEM/ML-DSA on `aws-lc-fips`, approved DRBG) and `MaxSpeed` (+ ChaCha20-Poly1305 / optional
  AEGIS-256 + X25519). Strict refuses non-approved algorithms at construction.
- **Parallel chunked STREAM AEAD** — 1 MiB frames, per-frame counter nonce, final-frame flag,
  4 KiB authenticated header bound as AAD, DEK key-commitment.
- **Overlapping I/O pipeline** — O_DIRECT/io_uring (Linux), overlapped (Windows), F_NOCACHE
  (macOS); 1–4 MiB buffers; reader → rayon crypto pool → ordered writer with bounded backpressure.
- **Encrypt-once multi-recipient** — one random DEK; per-recipient ML-KEM wrap of the 32-byte DEK.
- **Adaptive compression** — sample-and-skip incompressible inputs; multithreaded zstd / lz4.
- **Hybrid combiner** — SP 800-56C concat-KDF with transcript binding (not XOR).
- **Operational edges** — resumable checkpoints, atomic temp→rename output, typed bad-block
  errors, flat RSS under sustained throughput.
- **DoD:** `criterion` benchmarks show the big-file path is **I/O-bound** on NVMe (within a small
  margin of raw read bandwidth); a `kill -9` mid-TB job resumes bit-exact; `FipsStrict` rejects
  every non-approved algorithm; STREAM truncation/reorder/splice attempts fail authentication.
- **Live risk:** `aws-lc-rs` AEAD nonce/streaming surface + AEGIS availability (§11-O7); FIPS
  approved-service boundary for ChaCha/X25519 (§11-O8); io_uring/O_DIRECT alignment (§11-O9).

### Phase 4 — ForgeFS block layer

- Raw block device open/read/write (`nix` POSIX / `windows-sys`), sector-size probing.
- `ForgeVolumeHeader` read/write with AEAD-wrapped key-slots.
- rayon-parallel AES-256-XTS keyed by sector index (data unit = sector number).
- Runtime assertions rejecting any unaligned buffer.
- **DoD:** round-trip on a loopback device (`losetup` / Windows VHD); unaligned writes
  rejected; tamper in header detected via AEAD tag failure.
- **Live risk:** platform ioctl numbers for sector/size probing (`BLKSSZGET`, `DKIOCGETBLOCKSIZE`,
  `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`).

### Phase 5 — Anti-forensic & anchoring

- Crypto-erase duress (destroy key-slots + TPM/Enclave sealed object).
- Hidden-volume offset math; outer free space filled with CSPRNG so the inner header is
  indistinguishable.
- TPM 2.0 seal/unseal (`tss-esapi`); Apple Secure Enclave seal via platform channel.
- **DoD:** post-duress VMK provably unrecoverable (key-slots + sealed object gone);
  deniability threat model documented; seal/unseal verified on ≥1 platform.
- **Live risk:** `tss-esapi` API + availability per platform; Enclave access requires the
  host app's entitlements (cannot be done purely in Rust on iOS).

### Phase 6 — CI cross-compilation

- Linux x86_64/aarch64 + Android (`cargo-ndk`: arm64-v8a, armeabi-v7a, x86_64).
- macOS universal `.dylib` (lipo) + iOS `xcframework` (device + lipo'd simulator).
- Windows x86_64 MSVC `.dll`.
- Release job publishes artifacts + a **manifest.json** of SHA-256 hashes; those hashes are
  also pinned in `hook/build.dart` source (supply-chain anchor, §5.3).
- **DoD:** every target builds in CI; `hook/build.dart` fetches → verifies → links, and
  falls back cleanly when the network is blocked.
- **Live risk:** xcframework packaging (static-lib vs framework); cargo-ndk version flags.

---

## Turn-by-turn implementation order

1. Scaffold workspace + `pubspec.yaml` + `Cargo.toml` + `error.rs` + `secret.rs`; get an empty
   cdylib building and a `pqforge_abi_version` symbol loadable from Dart.
2. Wire FRB v2 codegen; expose `abiVersion()`; implement the selector + fallback; **P1 DoD**.
3. ML-KEM + ML-DSA + KATs; **P2 DoD**.
4. Streaming AEAD + archive (functional baseline); **P3 DoD**.
5. Parallel STREAM AEAD + overlapping I/O pipeline + dual-profile suite + `criterion` benchmarks;
   **P3.5 DoD**.
6. ForgeFS block I/O + XTS + header (crypto-erase); loopback tests; **P4 DoD**.
7. Hidden volumes + duress + TPM/Enclave; threat-model doc; **P5 DoD**.
8. CI matrix + manifest + pinned-hash release flow; **P6 DoD**.

> Each step ends at a **compiling, tested checkpoint** — never a speculative dump. The
> blueprint is the contract; the code is built against it and verified at each DoD.
