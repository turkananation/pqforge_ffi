# pqforge_ffi ↔ pqforge — Integration State, the Hybrid/Classical Gap, and the Drop-in Fix

> **Status:** analysis + plan. Records what is built and validated today, the
> architectural disconnect between what was built and how `pqforge` is designed
> to be accelerated, and the phased fix. Companion to
> [`ARCHITECTURE_BLUEPRINT.md`](ARCHITECTURE_BLUEPRINT.md),
> [`ROADMAP.md`](ROADMAP.md), [`MILESTONE_TRACKERS.md`](MILESTONE_TRACKERS.md).
>
> **Date:** 2026-06-28 · **pqforge target:** v0.2.2 · **native:** aws-lc-rs 1.17 / aws-lc-sys 0.41

---

## 0. TL;DR

- **Built & validated (203 tests):** a complete native crypto engine — ML-KEM,
  ML-DSA, AES-256-GCM, ChaCha20-Poly1305, a KEM-DEM envelope, streaming AEAD, and
  a native zero-FFI file pipeline — each proven byte-interoperable between native
  AWS-LC and the pure-Dart `pqforge`, with `mlock`/zeroize/atomic hardening.
- **The disconnect:** that engine was wired into a **parallel, standalone API**
  (`PqForgeBackend` + its own `PFE1` envelope / stream / file formats). It
  **bypasses `pqforge`'s purpose-built drop-in seam** (`PqLattice.provider`), so
  it does **not** accelerate `pqforge`'s own envelopes, multi-recipient, **hybrid
  (X25519 + ML-KEM)**, or **CLI**. And the **classical layer was never built** —
  the envelope is pure-PQ, not the PQ+classical hybrid `pqforge` is centred on.
- **The fix (phased):** **α** implement `PqLatticeProvider` over the existing
  native C-ABI and register it → the *entire* `pqforge` toolkit (hybrid + CLI)
  runs accelerated in `pqforge`'s own formats; **β** accelerate the classical
  primitives (X25519/ECDH-P256/Ed25519/ECDSA-P256), the AEAD engine, and the RNG;
  **γ** the hybrid combiner (optional native).
- **Honest note:** the standalone native API is still useful (it owns a file
  pipeline `pqforge` lacks), but **Phase α is the missing bridge** that makes
  "this project accelerates pqforge" actually true.

---

## 1. Current build state (what exists and is validated)

All cross-backend / cross-layer interop is *proven by tests* — native AWS-LC and
pure-Dart `pqforge` produce byte-identical output.

| Layer | Native (AWS-LC) | Fallback (pqforge/PointyCastle) | Validation |
| --- | --- | --- | --- |
| ML-KEM-512/768/1024 | `crypto/kem.rs` | `pqforge` | encap⇄decap interop |
| ML-DSA-44/65/87 | `crypto/sign.rs` (+ seeded keygen) | `pqforge` | sign⇄verify interop **+ cross-impl seed KAT (byte-identical keys)** |
| AES-256-GCM | `crypto/aead.rs` | `pqforge` (PointyCastle GCM) | seal⇄open interop |
| ChaCha20-Poly1305 | `crypto/aead.rs` | PointyCastle `ChaCha20Poly1305` | seal⇄open interop |
| KEM-DEM envelope | — (Dart composition) | `lib/src/api/envelope.dart` | cross-backend; tamper/AAD/key-mismatch |
| Streaming AEAD (STREAM) | — (Dart composition) | `lib/src/api/stream.dart` | tamper/reorder/truncation/extension |
| **Native file pipeline** | `crypto/stream_file.rs` | `lib/src/api/file_cipher.dart` | **cross-LAYER interop with `PqForgeStream`**, atomic output |
| Key custody | `secret.rs` `PinnedSecret` (mlock + zeroize) | — | unit-tested |
| FFI boundary | `error.rs` (`catch_unwind` guard, status taxonomy) | `lib/src/backend/*` | panic→`internal`, ABI probe |

**Test totals:** 173 Dart + 30 Rust = **203, all green; `dart analyze` clean; zero warnings.**
Grounding artefacts: Sovereign Conclave [`EVIDENCE_LEDGER.md`](conclave/EVIDENCE_LEDGER.md) +
[verdict](conclave/verdicts/verdict-20260626T100227Z.md).

**This is a correct, well-tested native engine — but it stands beside `pqforge`, not inside it.**

---

## 2. How `pqforge` is designed to be accelerated (grounded facts)

Read from `pqforge` 0.2.2 source (pub cache):

### 2.1 The lattice drop-in seam — `PqLattice.provider`
`lib/src/algorithms/pq_lattice_provider.dart` defines `abstract interface class
PqLatticeProvider` with **exactly** the operations already implemented natively:

```dart
abstract interface class PqLatticeProvider {
  String get name;
  (Uint8List publicKey, Uint8List secretKey) kemGenerateKeyPair(PqKemAlgorithm a, {Uint8List? seed});
  (Uint8List ciphertext, Uint8List sharedSecret) kemEncapsulate(PqKemAlgorithm a, Uint8List pk, {Uint8List? nonce});
  Uint8List kemDecapsulate(PqKemAlgorithm a, Uint8List sk, Uint8List ct);
  (Uint8List, Uint8List) dsaGenerateKeyPair(PqSignatureAlgorithm a);
  (Uint8List, Uint8List) dsaGenerateKeyPairSeeded(PqSignatureAlgorithm a, Uint8List seed);
  Uint8List dsaSign(PqSignatureAlgorithm a, Uint8List sk, Uint8List msg, {Uint8List? context, bool preHash = false});
  bool dsaVerify(PqSignatureAlgorithm a, Uint8List pk, Uint8List msg, Uint8List sig, {Uint8List? context, bool preHash = false});
}

abstract final class PqLattice {
  static PqLatticeProvider provider = const PqPureDartLatticeProvider();
}
```

Its docstring is unambiguous about intent:

> *"This seam lets a host register a **hardware-accelerated backend** (e.g. an FFI
> binding to a NEON/AVX2-optimised PQClean or liboqs build) **without changing any
> caller**. … `PqLattice.provider = MyPqCleanFfiProvider();` … validate it with the
> conformance/agreement harness in `test/support/lattice_conformance.dart`."*

Every lattice op in `pqforge` (`PqKemPrimitives`, `PqSignaturePrimitives`) delegates
to `PqLattice.provider`. **Replace the provider → the whole toolkit is accelerated,
unchanged.** This is the "Drop-in Backend / seamless polyfill" pattern from the
project's founding design.

### 2.2 The hybrid layer (the "classical mixture" you asked about)
`lib/src/hybrid/`:
- **`PqClassicalHybrid`** — X25519 + ML-KEM key agreement, and ML-DSA + classical
  dual signatures. Classical algorithms (`pq_classical_hybrid.dart`):
  - Key agreement: **X25519** (32-byte keys/secret), via `package:cryptography`.
  - Signatures: **Ed25519** (`package:cryptography`) and **ECDSA-P256**
    (`PqEcdsaP256`, pure-Dart PointyCastle).
- **`PqForgeCombiner`** (`pq_hybrid_combiner.dart`) — folds the two shared secrets
  with **concatenate-then-HKDF**:
  ```text
  concatenatedSecret = classicalSharedSecret || postQuantumSharedSecret
  sessionKey         = HKDF(ikm: concatenatedSecret, salt, info, L)
  ```
  This is the IETF `draft-ietf-tls-hybrid-design` / `draft-kwiatkowski-tls-ecdhe-mlkem`
  construction — i.e. **exactly the combiner the blueprint flagged as correction
  C5 (concat-KDF, *not* XOR).** Profiles: `balanced` (SHA-256) / `heavy` (SHA-512).

### 2.3 The other seams
- **AEAD:** `PqForgeEngineProvider` selects an engine (`cryptography` or
  PointyCastle). Selectable, but there is **no documented seam to register a
  *native* engine**.
- **RNG:** `PqRandom.generator` is a process-wide swappable function — easy to
  route at a native FIPS DRBG.

### 2.4 Pluggability summary

| `pqforge` surface | Swappable seam? | Accelerate via |
| --- | --- | --- |
| ML-KEM / ML-DSA | ✅ `PqLattice.provider` | **Phase α (drop-in)** |
| RNG | ✅ `PqRandom.generator` | Phase β (trivial) |
| AEAD engine | ⚠️ selectable, no custom-engine seam | Phase β (needs a seam) |
| Classical (X25519/Ed25519/ECDSA-P256) | ❌ hard-wired to `cryptography`/PointyCastle | Phase β (needs a seam **or** higher-level native hybrid) |
| Hybrid combiner (HKDF) | ❌ internal | Phase γ (cheap; optional) |

---

## 3. The disconnect — precisely

What was built: native ML-KEM/ML-DSA/AEAD primitives wired into a **new parallel
API** — `PqForgeBackend` (contract), `FallbackBackend`, `NativeBackend`, a `PqForge`
selector, plus `PqForgeEnvelope` (`PFE1` format), `PqForgeStream`, and
`PqForgeFileCipher`.

The problems that creates:

1. **It bypasses `PqLattice.provider`.** Nothing in `pqforge` calls the native
   code. So `pqforge`'s envelopes, `PqForgeMultiRecipient`, `PqForgeHybrid*`, the
   streaming services, and **the CLI remain pure-Dart** — unaccelerated. The native
   engine accelerates only *its own* parallel surface.
2. **No classical layer.** X25519 / Ed25519 / ECDSA-P256 were never touched, so the
   **hybrid PQ+classical mixture — the heart of `pqforge` — does not exist** in
   pqforge_ffi. `PqForgeEnvelope` is pure ML-KEM.
3. **Divergent wire format.** `PFE1` (the standalone envelope) ≠ `pqforge`'s `PQF1`.
   A file encrypted by the `pqforge` CLI cannot be opened by `PqForgeEnvelope` and
   vice-versa. For a true *drop-in accelerator* the formats must be `pqforge`'s.

### Two integration models

| | **Model A — standalone reimplementation** (what was built) | **Model B — drop-in provider / polyfill** (what `pqforge` is built for) |
| --- | --- | --- |
| How | New native API + new formats | Implement `PqLatticeProvider`; register it |
| Accelerates | only pqforge_ffi's own API | **all of `pqforge`** (envelopes, hybrid, multi-recipient, CLI) |
| Formats | new (`PFE1`) | `pqforge`'s own (`PQF1`) — full toolkit interop |
| Classical/hybrid | absent | inherited from `pqforge` (and accelerated in Phase β) |
| New code | large | small (wrap existing C-ABI) |

**Model B is the intended design and the high-leverage path.** Model A's outputs
remain useful (a standalone native API + a file pipeline `pqforge` lacks), but they
are not "accelerating pqforge."

---

## 4. The fix — Phase α: the drop-in lattice provider

Wrap the **existing native C-ABI** as a `PqLatticeProvider` and register it. No new
Rust is required for the common path.

```dart
// lib/src/integration/native_lattice_provider.dart  (Phase α)
import 'package:pqforge/pqforge.dart' as pq;

/// Registers the native AWS-LC engine as pqforge's lattice backend, so the whole
/// pqforge toolkit (envelopes, multi-recipient, hybrid, CLI) is hardware-accelerated.
class NativePqforgeLatticeProvider implements pq.PqLatticeProvider {
  NativePqforgeLatticeProvider(this._native, {pq.PqLatticeProvider? fallback})
      : _fallback = fallback ?? const pq.PqPureDartLatticeProvider();

  final NativeBackend _native;            // existing native KEM/DSA bindings
  final pq.PqLatticeProvider _fallback;   // for ops the native API can't honour (below)

  @override
  String get name => 'pqforge-ffi-awslc';

  @override
  (Uint8List, Uint8List) kemGenerateKeyPair(pq.PqKemAlgorithm a, {Uint8List? seed}) {
    if (seed != null) return _fallback.kemGenerateKeyPair(a, seed: seed); // see §4.1
    final kp = _native.kemGenerate(a);
    return (kp.publicKey, kp.secretKey);
  }

  @override
  (Uint8List, Uint8List) kemEncapsulate(pq.PqKemAlgorithm a, Uint8List pk, {Uint8List? nonce}) {
    if (nonce != null) return _fallback.kemEncapsulate(a, pk, nonce: nonce);  // see §4.1
    final e = _native.kemEncapsulate(a, pk);
    return (e.ciphertext, e.sharedSecret);
  }

  @override
  Uint8List kemDecapsulate(pq.PqKemAlgorithm a, Uint8List sk, Uint8List ct) =>
      _native.kemDecapsulate(a, sk, ct);

  @override
  (Uint8List, Uint8List) dsaGenerateKeyPair(pq.PqSignatureAlgorithm a) {
    final kp = _native.signGenerate(a);
    return (kp.publicKey, kp.secretKey);
  }

  @override
  (Uint8List, Uint8List) dsaGenerateKeyPairSeeded(pq.PqSignatureAlgorithm a, Uint8List seed) {
    // Native: pqforge_mldsa_keygen_from_seed — already PROVEN byte-identical to
    // pqforge's seeded keygen (cross-implementation KAT). Add a NativeBackend wrapper.
    final kp = _native.signGenerateFromSeed(a, seed);
    return (kp.publicKey, kp.secretKey);
  }

  @override
  Uint8List dsaSign(pq.PqSignatureAlgorithm a, Uint8List sk, Uint8List msg,
      {Uint8List? context, bool preHash = false}) {
    if ((context != null && context.isNotEmpty) || preHash) {
      return _fallback.dsaSign(a, sk, msg, context: context, preHash: preHash); // see §4.1
    }
    return _native.sign(a, sk, msg);
  }

  @override
  bool dsaVerify(pq.PqSignatureAlgorithm a, Uint8List pk, Uint8List msg, Uint8List sig,
      {Uint8List? context, bool preHash = false}) {
    if ((context != null && context.isNotEmpty) || preHash) {
      return _fallback.dsaVerify(a, pk, msg, sig, context: context, preHash: preHash);
    }
    return _native.verify(a, pk, msg, sig);
  }
}

// Usage (host app / CLI, once at startup):
//   final native = NativeBackend.open(libPath);
//   pq.PqLattice.provider = NativePqforgeLatticeProvider(native);
//   // …all pqforge crypto is now accelerated, unchanged.
```

### 4.1 API-mismatch constraints (verified against aws-lc-rs source — the crux)

`pqforge`'s provider interface is richer than aws-lc-rs's API in three places.
These are **real** and dictate the fall-through rules above:

| `pqforge` provider feature | aws-lc-rs reality | Rule |
| --- | --- | --- |
| `kemGenerateKeyPair(seed:)` | ML-KEM has **no seeded keygen** (only randomized `DecapsulationKey::generate`) | seed ⇒ **fall through** to pure-Dart |
| `kemEncapsulate(nonce:)` | `EncapsulationKey::encapsulate()` is **randomized**, no nonce input | nonce ⇒ **fall through** |
| `dsaSign(context:, preHash:)` | `PqdsaKeyPair::sign(msg, &mut sig)` — **no context / no HashML-DSA** | non-empty context or preHash ⇒ **fall through** |
| `dsaGenerateKeyPairSeeded` | `PqdsaKeyPair::from_seed(32-byte)` exists ✅ | **native** (KAT-proven byte-identical) |
| `kemDecapsulate`, `dsaVerify`, plain `dsaSign` | direct equivalents | **native** |

(Two tiny `NativeBackend` additions are needed: `signGenerateFromSeed` — the C-ABI
`pqforge_mldsa_keygen_from_seed` already exists and is symbol-exported — and exposing
the provider wrapper.)

### 4.2 Conformance
`pqforge` requires a provider to be **byte-identical on the deterministic ops**.
Those are `kemDecapsulate`, `dsaVerify`, and `dsaGenerateKeyPairSeeded` — **all
already proven** by the existing cross-backend tests and the ML-DSA seed KAT. The
randomized ops (keygen, encapsulate, sign) need only round-trip / verify, also
proven. Phase α adds: run `pqforge`'s `test/support/lattice_conformance.dart`
harness against `NativePqforgeLatticeProvider`.

### 4.3 What Phase α delivers
Registering the provider accelerates the **lattice math** — which the provider
docstring calls *"the throughput wall for per-file PQC in tight folder loops"* —
across **all** of `pqforge`: `PqForge` service, `PqEnvelope`/`PQF1`,
`PqForgeMultiRecipient`, **`PqForgeHybridKeyAgreement` / `PqForgeHybridSigner`**, the
streaming services, and the **CLI**. The classical half and the AEAD stay pure-Dart
until Phase β, but the heaviest cost is gone.

---

## 5. The fix — Phase β: accelerate the rest of the hybrid mixture

To accelerate the *classical* half (and thus make hybrid fully native) and the AEAD:

- **RNG (trivial):** `PqRandom.generator = nativeRandomBytes` backed by AWS-LC's
  DRBG (`aws_lc_rs::rand::SystemRandom`) — gives a FIPS-validated DRBG for the strict
  profile.
- **Classical primitives:** aws-lc-rs **does** provide them —
  `aws_lc_rs::agreement::{X25519, ECDH_P256}` and
  `aws_lc_rs::signature::{Ed25519KeyPair, EcdsaKeyPair}` (exact API to confirm at
  implementation, as was done for KEM/DSA). New C-ABI: `pqforge_x25519_*`,
  `pqforge_ecdh_p256_*`, `pqforge_ed25519_*`, `pqforge_ecdsa_p256_*`.
  - **Blocker:** `pqforge` 0.2.2 has **no classical provider seam** — `PqClassicalHybrid`
    is hard-wired to `package:cryptography`/PointyCastle. Two options:
    - **β-up (preferred):** add a `PqClassicalProvider` seam to `pqforge` upstream
      (mirroring `PqLatticeProvider`), then register a native one. Clean, symmetric.
    - **β-side:** implement the hybrid operations natively at a higher level
      (native KEM + native X25519 + native HKDF), emitting `pqforge`-compatible
      hybrid output. More work; must match `pqforge`'s hybrid wire format.
- **AEAD engine:** same shape — `pqforge`'s `PqForgeEngineProvider` selects engines
  but lacks a custom-native-engine seam; needs a small upstream addition or a
  higher-level native AEAD path. (The native AES-GCM/ChaCha primitives already
  exist and are interop-proven.)

---

## 6. The fix — Phase γ: the combiner

`PqForgeCombiner` is concatenate-then-HKDF (SHA-256/512). It is cheap and can stay
pure-Dart, or move to AWS-LC HKDF for a fully in-module FIPS path. Low priority; it
is not a throughput bottleneck and the construction is already correct (matches
blueprint C5).

---

## 7. Where the hybrid mixture lives (direct answer)

The PQ+classical mixture is **entirely in `pqforge`'s Dart `hybrid/` layer**
(`PqClassicalHybrid` + `PqForgeCombiner`), which pqforge_ffi has not touched.
pqforge_ffi today accelerates only the **lattice + AEAD primitives**, and only
within its **own parallel API** — not through `pqforge`. The hybrid therefore:
- **is not accelerated** (its lattice half runs pure-Dart because the provider seam
  is unused), and
- **is not present** in pqforge_ffi's own surface (the standalone envelope is
  pure-PQ).

Phase α fixes the first (hybrid's lattice half becomes native via the provider);
Phase β fixes the second (the classical half becomes native too).

---

## 8. Integration milestone tracker

```markdown
### Phase α — drop-in lattice provider
- [ ] NativeBackend.signGenerateFromSeed (wraps existing pqforge_mldsa_keygen_from_seed)
- [ ] NativePqforgeLatticeProvider implements PqLatticeProvider (with §4.1 fall-throughs)
- [ ] `PqLattice.provider = NativePqforgeLatticeProvider(...)` wiring + reset helper
- [ ] Passes pqforge's test/support/lattice_conformance.dart against the native provider
- [ ] End-to-end: a pqforge envelope/hybrid op runs accelerated and round-trips
- [ ] Seed/nonce/context fall-throughs verified to match pure-Dart byte-for-byte

### Phase β — classical + AEAD + RNG
- [ ] PqRandom.generator → AWS-LC DRBG; deterministic-disable for tests
- [ ] Native C-ABI: X25519 + ECDH-P256 agreement (cross-backend vs pqforge)
- [ ] Native C-ABI: Ed25519 + ECDSA-P256 sign/verify (cross-backend vs pqforge)
- [ ] Decision + implementation of the classical seam (β-up upstream vs β-side native hybrid)
- [ ] AEAD engine seam / native engine; hybrid envelope fully native end-to-end

### Phase γ — combiner
- [ ] (optional) native HKDF combiner; parity test vs PqForgeCombiner
```

---

## 9. Open decisions

1. **Primary surface.** Keep *both* — (i) the standalone native API (selector,
   envelope, stream, **file pipeline** — which `pqforge` lacks) and (ii) the
   drop-in provider — sharing one native C-ABI? (Recommended: yes.) Or fold the
   standalone API into pqforge-compatible formats?
2. **Format alignment.** Should `PqForgeEnvelope` adopt `pqforge`'s `PQF1` format
   for full CLI interop, or remain a separate, simpler standalone format?
3. **Upstream vs side.** Phase β classical: add a `PqClassicalProvider` seam to
   `pqforge` upstream (clean, needs a PR), or build native hybrid at a higher level
   (self-contained, must match wire format)?
4. **Seeded KEM keygen.** aws-lc-rs cannot do it; accept the pure-Dart fall-through,
   or treat seeded KEM keygen as unsupported on the native provider?

---

## 10. Appendix — provider ↔ native C-ABI mapping

| `PqLatticeProvider` method | Native C-ABI symbol | Notes |
| --- | --- | --- |
| `kemGenerateKeyPair` (no seed) | `pqforge_mlkem_keygen` | native |
| `kemEncapsulate` (no nonce) | `pqforge_mlkem_encapsulate` | native |
| `kemDecapsulate` | `pqforge_mlkem_decapsulate` | native; deterministic ⇒ conformance-checked |
| `dsaGenerateKeyPair` | `pqforge_mldsa_keygen` | native |
| `dsaGenerateKeyPairSeeded` | `pqforge_mldsa_keygen_from_seed` | native; **KAT-proven byte-identical** |
| `dsaSign` (empty ctx, no preHash) | `pqforge_mldsa_sign` | native; else fall through |
| `dsaVerify` (empty ctx, no preHash) | `pqforge_mldsa_verify` | native; deterministic ⇒ conformance-checked |
| `kemGenerateKeyPair(seed:)` | — | pure-Dart fall-through (aws-lc lacks seeded KEM keygen) |
| `kemEncapsulate(nonce:)` | — | pure-Dart fall-through (aws-lc encapsulate is randomized) |
| `dsaSign/Verify(context:/preHash:)` | — | pure-Dart fall-through (aws-lc ML-DSA has no ctx/HashML-DSA) |
