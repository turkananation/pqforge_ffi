# pqforge_ffi — Milestone Verification Trackers

> Companion to [`ARCHITECTURE_BLUEPRINT.md`](ARCHITECTURE_BLUEPRINT.md) and
> [`ROADMAP.md`](ROADMAP.md). Check a box only when its **evidence** exists — a passing test,
> a KAT match, a debugger/valgrind observation, a green CI job. A phase is complete when all
> its boxes are checked **and** the corresponding roadmap Definition-of-Done is met.

## P1 — Foundation

- [ ] Cargo workspace + Dart package build side-by-side
- [ ] `PqForgeError` maps every Rust failure to a typed Dart exception
- [ ] No panic can unwind across the FFI boundary (`catch_unwind` / FRB guard)
- [ ] Pure-Dart fallback passes the full test suite with native lib **ABSENT**
- [ ] Selector logs which backend (native vs polyfill) is live + why

## P2 — Crypto core

- [ ] ML-KEM-768 encap/decap matches FIPS 203 KAT
- [ ] ML-KEM-1024 encap/decap matches FIPS 203 KAT
- [ ] ML-DSA-65/87 sign/verify matches FIPS 204 KAT
- [ ] Every secret type derives `ZeroizeOnDrop`; verified zeroed under debugger
- [ ] `mlock`/`VirtualLock` applied to key pages; core-dump + hibernation guards on
- [ ] Constant-time tag/secret comparison (`subtle`) everywhere it matters

## P3 — Streaming / archive (functional baseline)

- [ ] Bulk encrypt streams in bounded RAM (no full-file load)
- [ ] Zstd+tar+AEAD round-trips bit-exact on a 10 GB corpus
- [ ] `memmap2` path verified for a directory with >100k files
- [ ] Progress Stream emits monotonic byte counters; cancellation honored

## P3.5 — TB-scale data path & dual-profile

- [ ] Dual-profile selectable; `FipsStrict` refuses ChaCha20-Poly1305 / X25519 / AEGIS-256 at construction
- [ ] Parallel STREAM AEAD: per-frame counter nonce unique, final-frame flag, 4 KiB header bound as AAD
- [ ] DEK key-commitment in header (closes partitioning-oracle on multi-recipient objects)
- [ ] Multi-recipient encrypts the payload once; per-recipient ML-KEM wrap of the 32-byte DEK only
- [ ] Hybrid combiner = concat-KDF with transcript binding (not XOR); KAT-checked
- [ ] Big-file path is **I/O-bound** on NVMe (within ~Y% of raw sequential read bandwidth)
- [ ] Overlapping pipeline: O_DIRECT/io_uring (Linux), overlapped (Windows), F_NOCACHE (macOS)
- [ ] Adaptive compression: incompressible inputs skipped; multithreaded zstd / lz4 path verified
- [ ] Resumable: `kill -9` mid-TB job resumes bit-exact from checkpoint
- [ ] Atomic output: temp → fsync → rename; no corrupt-but-authenticating file on abort
- [ ] Bad-block / partial-read is a typed error, never a panic; partial output unlinked
- [ ] Backpressure holds RSS flat under sustained TB throughput
- [ ] `criterion` benchmarks + CI perf-regression gate; GB/s-per-platform table published
- [ ] STREAM truncation / frame-reorder / cross-file splice all fail authentication

## P4 — ForgeFS

- [ ] Sector size probed correctly on 512e and 4Kn media
- [ ] Unaligned write attempts rejected by runtime assertion
- [ ] AES-256-XTS round-trips on a loopback device
- [ ] rayon parallelism scales across cores with zero data races (loom/TSan)
- [ ] Header tamper detected via AEAD tag failure

## P5 — Anti-forensic

- [ ] Duress = crypto-erase: VMK provably unrecoverable post-trigger
- [ ] Duress path bypasses normal error handling and flushes (FUA/fsync)
- [ ] Hidden-volume free space is CSPRNG-indistinguishable (ciphertext layer)
- [ ] Deniability threat model + limitations documented and shipped
- [ ] TPM 2.0 seal/unseal verified on Linux
- [ ] Secure Enclave seal/unseal verified on iOS/macOS via host entitlements

## P6 — CI

- [ ] Linux x86_64 + aarch64 `.so` build
- [ ] Android arm64-v8a + armeabi-v7a + x86_64 `.so` build (cargo-ndk)
- [ ] macOS universal `.dylib` (lipo x86_64 + arm64)
- [ ] iOS xcframework (device aarch64 + lipo'd simulator) packaged
- [ ] Windows x86_64 MSVC `.dll` build
- [ ] `manifest.json` published; pinned hashes in `build.dart` match release
- [ ] `build.dart`: fetch → SHA-256 verify → link; falls back on network failure
