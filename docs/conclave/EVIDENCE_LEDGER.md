# Sovereign Conclave — Evidence Ledger (FROZEN)

**Deliberation:** Grounding & sequencing of pqforge_ffi Phase 1 + Phase 2 implementation.
**Frozen:** 2026-06-26T10:02:27Z · **Quorum:** feynman, zhukov, washington, oppenheimer,
lee-kuan-yew, von-neumann + Marshall (verifier).

## Decision frame (Round 0.5)

**Decision (one sentence):** How to sequence and scope Phase 1 (Rust+Dart foundation +
pure-Dart fallback + error taxonomy + FFI ABI) and Phase 2 (ML-KEM/ML-DSA via aws-lc-rs +
zeroize + mlock) so **every checkpoint compiles, passes tests, and is validatable in THIS
environment**, with testing as a first-class citizen.

**Options (incl. null):**

- **A — FRB-first full stack:** install `flutter_rust_bridge_codegen`, build non-FIPS
  aws-lc-rs, wire FRB bindings for P1+P2 together.
- **B — Raw C-ABI foundation; FRB+FIPS deferred:** P1 via hand-written `extern "C"` + `dart:ffi`
  (no FRB toolchain), validated end-to-end; P2 adds non-FIPS aws-lc-rs behind the same C-ABI;
  FRB & FIPS deferred to a later phase / CI.
- **C — Pure-Dart-first:** build + validate the Dart backend contract + error taxonomy +
  fallback (wired to `pqforge`) first; defer all native/Rust until the Dart contract is proven.
- **NULL — do nothing:** keep documenting; write no code.

**Optimizing for:** validatable results at each checkpoint; grounding (no speculative code);
not getting blocked by missing toolchain (FRB codegen, Go) or RAM.

**Load-bearing assumptions:** (a) non-FIPS aws-lc-rs compiles here (swap covers RAM, E3/E6);
(b) FRB codegen install is feasible but adds time/risk + a moving API (E5); (c) FIPS is a
CI/later gate (E6); (d) `pqforge` v0.2.2 API can back the fallback — needs verification (E9).

## Frozen ledger

| ID | Item | Provenance | Handling |
| --- | --- | --- | --- |
| E1 | Host = Linux x86_64, kernel 7.0.11 | `uname -a` recon | primary |
| E2 | CPU 8 cores; ISA `aes,avx2,avx512f,pclmulqdq,sha_ni` (full HW AES/GHASH/SHA; AVX-512 ⇒ VAES-class GCM/XTS) | `/proc/cpuinfo` recon | primary |
| E3 | 11 GiB RAM (~1.5 GiB free) **but** 15 GiB swap (~7.4 GiB free) + 700 GB disk ⇒ large C builds won't OOM, only slow | `free -h` / `df -h` recon | primary |
| E4 | Present: rustc/cargo 1.94.1, dart 3.12.0, flutter 3.44.0, cmake 3.28.3, clang 21, gcc 13.3, make 4.3, ninja 1.11, perl, git 2.43, losetup | `--version` recon | primary |
| E5 | `flutter_rust_bridge_codegen` **MISSING** (not installed) | `command -v` recon | primary |
| E6 | Go **MISSING** (observed); AWS-LC FIPS module build requires Go (reference) ⇒ `--features fips` not locally buildable yet; non-FIPS aws-lc-rs path (cmake+cc+perl) IS satisfiable | recon + reference | observed + reference |
| E7 | rustup targets installed: `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-gnu` only (no Android/iOS/macOS) | `rustup target list` recon | primary |
| E8 | cargo registry reachable (`cargo search` works ⇒ online builds OK); `zeroize` latest = 1.9.0 | `cargo search` recon | primary |
| E9 | `pqforge` IS on pub.dev v0.2.2 (pure-Dart ML-KEM/ML-DSA envelopes, streaming, multi-recipient, CLI) — fallback backend is real & resolvable; exact public API names UNVERIFIED | pub.dev API | primary + gap |
| E10 | `dart pub get` succeeds on the scaffold (Dart side healthy) | recon | primary |
| E11 | aws-lc-rs ML-KEM expected via `unstable` feature; ML-DSA (FIPS 204) public-API exposure UNVERIFIED (blueprint §11-O2) | prior assertion | contested/unverified |
| E12 | Repo = bare dart package scaffold + `docs/` (blueprint, roadmap, trackers) | local files | primary |

> Frozen. Every factual claim in deliberation must cite a ledger ID; uncited claims are
> opinion and Marshall will flag them. New evidence after freeze is appended as `E-next` and
> marked post-freeze.

## Post-freeze evidence (appended after Round 1 — D-6)

| ID | Item | Provenance | Handling |
| --- | --- | --- | --- |
| E13 | `pqforge` 0.2.2 public API observed: `PqForge`, `PqKeyPair`, `PqKemAlgorithm`, `PqKemEncapsulation`, `PqKemPrimitives`, `PqSignatureAlgorithm`, `PqSignaturePrimitives`, `PqForgeException`, hybrid + streaming + multi-recipient services ⇒ fallback backend is real & wireable | pub-cache source inspection | primary (settles E9) |
| E14 | `aws-lc-rs` exposes ML-DSA via `aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_65_SIGNING, ML_DSA_65}` and ML-KEM via the `unstable` kem module | aws-lc-rs repo via Context7 | primary (settles E11) |

> **Verdict:** [`verdicts/verdict-20260626T100227Z.md`](verdicts/verdict-20260626T100227Z.md) —
> advises **B-spine + C-fallback as co-equal Phase 1, A (FRB) deferred**. Confidence HIGH
> (Phase 1) / MEDIUM (Phase 2). Only remaining unobserved decisive item: E6 (does non-FIPS
> aws-lc-rs build locally) — settled when Phase 2 compiles.
