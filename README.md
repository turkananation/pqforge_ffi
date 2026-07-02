# pqforge_ffi

Hardware-accelerated, FIPS-aligned **post-quantum cryptography** for Dart and
Flutter — a native [AWS-LC](https://github.com/aws/aws-lc) (via
[`aws-lc-rs`](https://crates.io/crates/aws-lc-rs)) engine with a transparent,
byte-compatible **pure-Dart fallback**.

`pqforge_ffi` is the acceleration companion to the pure-Dart
[`pqforge`](https://pub.dev/packages/pqforge) toolkit. Register its native
providers and the **entire** `pqforge` stack — ML-KEM / ML-DSA, the X25519 +
Ed25519 hybrid handshake, KEM-DEM envelopes, multi-recipient, and the CLI — runs
on AWS-LC with no change to any caller. Where the native engine can't perform an
operation, it falls through to pure Dart, so behaviour is identical and never
degrades.

## Features

- **Drop-in acceleration for `pqforge`** through its swappable provider seams —
  no API changes, register once at startup.
  - `PqLattice.provider` → ML-KEM (512/768/1024) and ML-DSA (44/65/87).
  - `PqClassical.provider` → X25519 key agreement and Ed25519 signatures.
- **Standalone accelerated primitives** via the `PqForge` facade: KEM, signatures,
  AEAD (AES-256-GCM, ChaCha20-Poly1305), single-shot KEM-DEM envelopes, and a
  streaming/TB-scale pipeline.
- **Byte-for-byte interoperable** with the pure-Dart fallback: deterministic
  operations (ML-DSA seeded keygen, X25519 ECDH, Ed25519, the STREAM wire format)
  are proven identical; a container sealed by the native engine opens on pure
  Dart and vice-versa.
- **FIPS-lineage primitives** (FIPS 203 ML-KEM, FIPS 204 ML-DSA, RFC 7748 X25519,
  RFC 8032 Ed25519) with a panic-guarded C-ABI, zeroized transit secrets, and
  constant-time verification inherited from `pqforge`.
- **Pure-Dart everywhere by default** — the native library is optional; without
  it, everything still works on the fallback.

## Two ways to use it

### 1. Accelerate the whole `pqforge` toolkit (recommended)

Register the native providers once at startup. Every `pqforge` API — envelopes,
the hybrid `initiate`/`accept` handshake, signing — then runs on AWS-LC:

```dart
import 'package:pqforge/pqforge.dart';
import 'package:pqforge_ffi/pqforge_ffi.dart';

void main() async {
  const lib = 'rust/target/release/libpqforge_core.so'; // see "Native library"

  // Lattice (ML-KEM / ML-DSA) and classical (X25519 / Ed25519) seams.
  PqLattice.provider = NativePqforgeLatticeProvider.open(lib);
  PqClassical.provider = NativePqforgeClassicalProvider.open(lib);

  // ...from here, ordinary pqforge code is hardware-accelerated, unchanged...
  final forge = PqForge(profile: PqForgeProfile.balanced);
  final keys = forge.generateKeys();
  final sealed = forge.encrypt(
    keys.kemKeyPair.publicKey,
    Uint8List.fromList('attack at dawn'.codeUnits),
    signerSecretKey: keys.signatureKeyPair.secretKey,
  );
  final opened = forge.decrypt(
    keys.kemKeyPair.secretKey,
    sealed,
    signerPublicKey: keys.signatureKeyPair.publicKey,
  );

  // Restore the pure-Dart engine at any time:
  PqLattice.useDefault();
  PqClassical.useDefault();
}
```

Operations AWS-LC can't do — seeded ML-KEM keygen, nonce'd encapsulation,
context/pre-hash ML-DSA signing, and ECDSA-P256 — transparently fall through to
the pure-Dart provider, preserving the full contract.

### 2. Standalone accelerated primitives

The `PqForge` facade resolves the best available backend once and exposes the
primitives directly. Pass a `nativeLibraryPath` to opt into acceleration
(otherwise it uses the always-available pure-Dart fallback):

```dart
import 'dart:typed_data';
import 'package:pqforge_ffi/pqforge_ffi.dart';

final pq = PqForge.instance(
  nativeLibraryPath: 'rust/target/release/libpqforge_core.so',
);
print('accelerated: ${pq.isAccelerated}'); // false if the library is absent

// ML-KEM-768 encapsulate / decapsulate
const kem = PqKemAlgorithm.mlKem768;
final kp = pq.generateKemKeyPair(kem);
final enc = pq.encapsulate(kem, kp.publicKey);
final shared = pq.decapsulate(kem, kp.secretKey, enc.ciphertext);
// `shared` now equals `enc.sharedSecret`.

// ML-DSA-65 sign / verify
const dsa = PqSignatureAlgorithm.mlDsa65;
final sk = pq.generateSignatureKeyPair(dsa);
final msg = Uint8List.fromList('hello'.codeUnits);
final sig = pq.sign(dsa, sk.secretKey, msg);
assert(pq.verify(dsa, sk.publicKey, msg, sig));
```

A bad library path, ABI mismatch, or failed AWS-LC self-test degrades **silently**
to the pure-Dart fallback — you never get a crash, just `isAccelerated == false`.

## Cookbook

**Encrypt to a recipient's public key (single-shot KEM-DEM envelope):**

```dart
// ML-KEM → HKDF-SHA256 → AES-256-GCM; header bound as AAD, fresh key per envelope.
final envelope = pq.sealEnvelope(
  PqKemAlgorithm.mlKem768, recipientPublicKey, plaintext, aad: context);
final plain = pq.openEnvelope(recipientSecretKey, envelope, aad: context);
```

**AEAD packet (AES-256-GCM or ChaCha20-Poly1305):**

```dart
final ct = pq.aeadSeal(PqAeadAlgorithm.aes256Gcm, key, nonce, plaintext, aad);
final pt = pq.aeadOpen(PqAeadAlgorithm.aes256Gcm, key, nonce, ct, aad);
```

**Streaming AEAD for large / TB-scale data (the `age`-style STREAM construction):**

```dart
// Per-frame nonce = counter ‖ last-flag; tamper, reorder, and truncation all
// fail authentication. Memory-bounded; the key MUST be unique per stream.
final frames = pq.stream.seal(byteStream, key: key); // Stream<Uint8List>
final plaintext = pq.stream.open(frames, key: key);
```

**Encrypt a file entirely in native code (zero per-chunk FFI):**

```dart
final cipher = PqForgeFileCipher.open('rust/target/release/libpqforge_core.so');
await cipher.seal('big.bin', 'big.pqfs', key: key);   // atomic temp+rename
await cipher.open('big.pqfs', 'big.out', key: key);   // throws on tamper
```

The file pipeline uses the **same STREAM wire format** as `pq.stream`, so a file
sealed natively opens through the Dart stream and vice-versa.

## Algorithms

| Family | Values |
| --- | --- |
| KEM (FIPS 203) | `PqKemAlgorithm.mlKem512` · `mlKem768` · `mlKem1024` |
| Signature (FIPS 204) | `PqSignatureAlgorithm.mlDsa44` · `mlDsa65` · `mlDsa87` |
| Classical | X25519 (agreement) · Ed25519 (signature) — native; ECDSA-P256 — pure-Dart |
| AEAD | `PqAeadAlgorithm.aes256Gcm` · `chaCha20Poly1305` |

## Native library

The native engine is a Rust `cdylib` (`pqforge_core`) over `aws-lc-rs`. Build it
once, then point the providers / `PqForge.instance` at the output:

```bash
cd rust && cargo build --release
# → rust/target/release/{libpqforge_core.so | .dylib | pqforge_core.dll}
```

Automatic bundling via Dart Native Assets is planned; until then the library is
loaded by explicit path, and every entry point falls back to pure Dart when it
is absent — so code written against `pqforge_ffi` runs anywhere `dart run` does.

## Design & guarantees

- **Fallback is a first-class path, not an error case.** The pure-Dart engine is
  `pqforge` itself, so the fallback is a complete, audited implementation.
- **Determinism contract.** ML-DSA keygen-from-seed, X25519 ECDH, Ed25519
  (keygen + signatures), and the AEAD/STREAM wire formats are byte-identical
  across engines — verified by cross-implementation known-answer and
  agreement tests. ECDSA-P256 (RFC-6979 in `pqforge`, randomized in AWS-LC) is
  cross-verified rather than byte-compared, which is why it stays on pure Dart.
- **No panics across FFI.** Every native call is wrapped in a `catch_unwind`
  panic boundary that maps to a typed status; a null/invalid input returns a
  typed exception, never a crash. Verification never throws — it returns `false`.
- **Secret hygiene.** Secrets that transit Rust are held in `zeroize`d buffers;
  the file pipeline pins its key with `mlock` + zeroize.

## Status

Actively developed. The native crypto core (ML-KEM, ML-DSA, X25519, Ed25519,
AES-256-GCM, ChaCha20-Poly1305, STREAM, and the file pipeline) is implemented and
validated against the pure-Dart fallback; Native Assets auto-bundling and the
FIPS-strict AWS-LC profile are on the roadmap. Not yet security-audited by a third
party — review before production use with real key material.

## License

See [LICENSE](LICENSE).
