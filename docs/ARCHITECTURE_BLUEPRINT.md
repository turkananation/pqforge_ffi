# pqforge_ffi — Architecture Blueprint & Implementation Specification

> **Status:** DRAFT / pre-implementation blueprint. No code in this document has been
> compiled. It is an engineering specification to build against, not a release artifact.
>
> **Companion to:** [`pqforge`](https://github.com/turkananation/pqforge) (pub.dev) — the
> pure-Dart PQC toolkit that layers KEM-DEM envelopes, streaming AEAD and hybrid crypto
> over PointyCastle. `pqforge_ffi` is the hardware-accelerated native backend + drop-in
> fallback for that toolkit.
>
> **Document version:** 0.1.0 · **Target SDK:** Dart `^3.12` · **Toolchain:** Rust stable + FRB v2

---

## 0. Reality check & corrections to the original brief

This blueprint **deliberately diverges** from the original "NSA-grade" brief in four places
where the brief, taken literally, would ship a security defect or an unbackable claim. These
are not stylistic choices — they are the difference between a tool that works and one that
gives users false confidence.

| # | Brief said | Why it's wrong | What this blueprint does instead |
|---|------------|----------------|----------------------------------|
| C1 | "Overwrite Sector 0 with zeros, unrecoverable in < 2 ms." | On SSD/NVMe/eMMC the FTL + wear-levelling mean a *logical* overwrite of LBA 0 does **not** erase the physical NAND cells; the old header can survive in remapped blocks. A *durable* write needs `fsync`/FUA, which is not bounded at 2 ms. | **Crypto-erase** (user-selected). Duress destroys the header **key-slots** (the wrapped Volume Master Key), which is a few hundred bytes and reliably renders the VMK unrecoverable on *any* media. Best-effort plaintext wipe layered on top. See §7. |
| C2 | Hidden volumes "mathematically indistinguishable from CSPRNG free space." | The *ciphertext-looks-random* property is real and achievable. **System-wide** deniability is not — it leaks via filesystem metadata, OS hibernation/swap/prefetch, journals and wear-levelling. VeraCrypt ships explicit caveats for exactly this. | Build the indistinguishable-ciphertext layer **and** ship a documented threat model stating what deniability does and does not cover. See §7.3. |
| C3 | "FIPS 140-3 validated." | Linking `aws-lc-rs` does **not** validate *your* product. Validation requires the FIPS build variant (`aws-lc-fips-sys`), approved-mode operation with power-on self-tests, and confirming the algorithms are inside the validated boundary **for the exact version pinned**. | Use defensible language: "built on a FIPS-validated cryptographic module (AWS-LC)." Wire the FIPS-capable backend behind a feature flag; never assert product validation. See §6.4. |
| C4 | `hook/build.dart` using `native_assets_cli` `BuildConfig`/`BuildOutput`. | That API was restructured. Current API (verified against `dart-lang/native`) is `package:hooks` + `package:code_assets`. | Blueprint uses the current `build(args, (BuildInput, BuildOutputBuilder))` API throughout. See §5.3. |
| C5 | (From the earlier chat) hybrid combiner = "XOR or concatenate the two shared secrets." | A bare XOR/concat is not a sound KEM combiner; without transcript binding, one half can be re-encapsulated independently and the hybrid security proof collapses. | SP 800-56C-style concat-KDF with transcript binding: `HKDF(ss_pq ‖ ss_classical ‖ H(kem_ct ‖ classical_pub ‖ header))`. See §8.7. |
| C6 | (Implied) one AES-GCM pass over the whole file. | AES-GCM is safe for only ~64 GiB per (key, nonce) — the 32-bit block counter wraps — so a single GCM pass cannot cover a TB. Nonce reuse is catastrophic. | Parallel chunked **STREAM** AEAD: 1 MiB frames, per-frame counter nonce, final-frame flag, header bound as AAD. Fixes correctness *and* enables multi-core throughput. See §8.3. |

**Minor handled items:** `mlock`/`VirtualLock` do not protect against hibernation or core
dumps (we add `prctl(PR_SET_DUMPABLE, 0)` / `setrlimit(RLIMIT_CORE, 0)` guards); XTS already
performs ciphertext-stealing at the data-unit level, so fixed-size sector writes rarely need
explicit CTS; `aws-lc-rs` ML-DSA exposure is recent and is **flagged for verification at pin
time** (see §11).

---

## 1. Design pillars

1. **Zero-friction DX** — end users need no Rust/Cargo/CMake/NDK. Prebuilt binaries are
   fetched + verified by a Native Assets build hook; failure degrades to a pure-Dart polyfill.
2. **Multi-platform native core** — one Rust workspace cross-compiled to Linux, Android,
   macOS, iOS, Windows via a GitHub Actions matrix.
3. **FIPS-validated module under the hood** — ML-KEM (FIPS 203) and ML-DSA (FIPS 204) plus
   AEAD via AWS-LC, with AES-NI / ARMv8 Crypto Extensions / AVX2 / NEON acceleration.
4. **Deterministic secret hygiene** — all key material is `ZeroizeOnDrop`; live pages are
   `mlock`/`VirtualLock`-pinned with hibernation/core-dump guards.
5. **Bare-metal block encryption (ForgeFS)** — raw block I/O with rayon-parallel AES-256-XTS,
   sector-aligned, behind a crypto-erase-capable `ForgeVolumeHeader`.
6. **Anti-coercion engine** — crypto-erase duress, deniable hidden volumes, TPM 2.0 / Secure
   Enclave anchoring — each with an honest threat model.

### 1.1 Non-goals

- Web/Wasm hot-path acceleration (Dart FFI does not target the web; the web path uses the
  pure-Dart `pqforge` toolkit unchanged).
- A claim of certified FIPS 140-3 validation for *this package*.
- A claim of deniability against an adversary with full-system forensic access + coercion
  over time (see §7.3 threat model).

---

## 2. Repository structure

```text
pqforge_ffi/
├── pubspec.yaml                      # Dart package + native-assets + hook deps
├── analysis_options.yaml
├── CHANGELOG.md
├── README.md
├── LICENSE                           # dual: AGPL-3.0-or-later OR commercial
├── hook/
│   └── build.dart                    # Native Assets: fetch + SHA-256 verify + link, else fallback
├── lib/
│   ├── pqforge_ffi.dart              # public API surface (re-exports)
│   └── src/
│       ├── backend/
│       │   ├── backend.dart          # PqForgeBackend interface (the contract)
│       │   ├── native_backend.dart   # FRB-backed implementation
│       │   ├── fallback_backend.dart # pure-Dart (pqforge/PointyCastle) implementation
│       │   └── selector.dart         # runtime probe + selection + logging
│       ├── ffi/
│       │   └── frb_generated.dart    # GENERATED by flutter_rust_bridge_codegen
│       ├── api/
│       │   ├── kem.dart              # ML-KEM facade
│       │   ├── sign.dart             # ML-DSA facade
│       │   ├── aead.dart             # streaming AEAD facade
│       │   ├── archive.dart          # pack/unpack facade
│       │   └── volume.dart           # ForgeFS facade
│       └── model/
│           ├── errors.dart           # Dart-side PqForgeException hierarchy
│           └── progress.dart         # progress stream events
├── rust/
│   ├── Cargo.toml                    # workspace
│   ├── rust-toolchain.toml
│   └── crates/
│       └── pqforge_core/
│           ├── Cargo.toml
│           ├── build.rs
│           └── src/
│               ├── lib.rs            # FRB entrypoint (#[frb] api modules)
│               ├── error.rs          # PqForgeError + FFI panic boundary
│               ├── secret.rs         # Zeroizing wrappers + mlock/VirtualLock
│               ├── crypto/
│               │   ├── mod.rs
│               │   ├── kem.rs        # ML-KEM via aws-lc-rs
│               │   ├── sign.rs       # ML-DSA (aws-lc-rs | fips204 fallback)
│               │   ├── aead.rs       # AES-256-GCM / streaming AEAD
│               │   └── kdf.rs        # Argon2id + HKDF
│               ├── archive/
│               │   └── mod.rs        # zstd + tar + AEAD streaming
│               ├── disk/
│               │   ├── mod.rs
│               │   ├── blockdev.rs   # raw block I/O (nix | windows-sys)
│               │   ├── header.rs     # ForgeVolumeHeader (serde + AEAD)
│               │   ├── xts.rs        # rayon-parallel AES-256-XTS
│               │   └── duress.rs     # crypto-erase engine
│               └── anchor/
│                   ├── mod.rs
│                   ├── tpm.rs        # TPM 2.0 (tss-esapi)
│                   └── enclave.rs    # Apple Secure Enclave / Keychain
├── example/
│   └── pqforge_ffi_example.dart
├── test/
│   ├── kem_test.dart
│   ├── sign_test.dart
│   ├── fallback_test.dart            # passes with NO native lib present
│   └── volume_loopback_test.dart
├── docs/
│   ├── ARCHITECTURE_BLUEPRINT.md     # this file (spec/contract)
│   ├── ROADMAP.md                    # 6-phase plan + turn-by-turn order
│   └── MILESTONE_TRACKERS.md         # per-phase Definition-of-Done checkboxes
└── .github/
    └── workflows/
        └── release.yml               # cross-compile matrix + release + manifest
```

---

## 3. Execution roadmap (6 phases)

> **Moved to its own document:** [`ROADMAP.md`](ROADMAP.md) — the 6-phase plan, each with a
> Definition-of-Done and the live API risk to verify, plus the turn-by-turn implementation
> order. Progress is checked off in [`MILESTONE_TRACKERS.md`](MILESTONE_TRACKERS.md).

---

## 4. Milestone verification trackers

> **Moved to its own document:** [`MILESTONE_TRACKERS.md`](MILESTONE_TRACKERS.md) — per-phase
> checkbox trackers (P1–P6) to check off as each Definition-of-Done is met.

---

## 5. File blueprints

> All code below is a **specification target**, not compiled output. Sections flagged
> `⚠ VERIFY` depend on a library API that must be confirmed against the pinned version at
> implementation time (collected in §11).

### 5.1 `pubspec.yaml`

```yaml
name: pqforge_ffi
description: >-
  Hardware-accelerated, FIPS-module-backed post-quantum cryptography and full-disk
  encryption for Dart/Flutter. Native ML-KEM / ML-DSA / AEAD via AWS-LC with a transparent
  pure-Dart fallback.
version: 0.1.0
repository: https://github.com/turkananation/pqforge_ffi
issue_tracker: https://github.com/turkananation/pqforge_ffi/issues
topics: [cryptography, post-quantum, ffi, encryption, fips]

environment:
  sdk: ^3.12.0

dependencies:
  # Public toolkit this package accelerates + falls back to.
  pqforge: ^1.0.0
  # FRB runtime (must match the codegen CLI version pinned in CI).
  flutter_rust_bridge: ^2.7.0           # ⚠ VERIFY exact 2.x at pin time
  ffi: ^2.1.0
  meta: ^1.16.0
  logging: ^1.3.0

dev_dependencies:
  lints: ^6.0.0
  test: ^1.25.6
  # Used by hook/build.dart (hooks run in the package's resolution context).
  hooks: ^0.20.0                        # ⚠ VERIFY: the build-hook protocol package
  code_assets: ^0.20.0                  # ⚠ VERIFY: pairs with `hooks`
  http: ^1.2.0
  crypto: ^3.0.0                        # sha256 for artifact verification
  path: ^1.9.0

# Opt in to the Native Assets / build-hook experiment until it stabilizes.
# (Flag name is SDK-version dependent — see §11-O1.)
```

### 5.2 `rust/Cargo.toml` (workspace) and member crate

```toml
# rust/Cargo.toml  — workspace root
[workspace]
resolver = "2"
members = ["crates/pqforge_core"]

[workspace.package]
edition = "2021"
license = "AGPL-3.0-or-later OR LicenseRef-Commercial"
rust-version = "1.82"

[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "unwind"        # REQUIRED: catch_unwind needs unwinding, not abort
strip = "symbols"
```

```toml
# rust/crates/pqforge_core/Cargo.toml
[package]
name = "pqforge_core"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[lib]
crate-type = ["cdylib", "staticlib"]   # cdylib for desktop/mobile dynamic; staticlib for iOS xcframework

[dependencies]
# --- FFI bridge ---
flutter_rust_bridge = "=2.7.0"          # ⚠ VERIFY: must equal the codegen CLI version

# --- Cryptography (FIPS-validated module) ---
# `unstable` exposes the ML-KEM (kem) API. `fips` selects the validated module build.
aws-lc-rs = { version = "1.13", features = ["unstable"] }   # ⚠ VERIFY ML-DSA exposure (§11-O2)
# Pure-Rust ML-DSA fallback if aws-lc-rs does not expose FIPS 204 in the pinned version:
fips204 = { version = "0.4", optional = true }              # RustCrypto; ⚠ VERIFY crate+version

# --- KDF ---
argon2 = "0.5"                          # Argon2id for password -> KEK
hkdf = "0.12"
sha2 = "0.10"

# --- Symmetric / disk ---
aes = "0.8"
xts-mode = "0.5"                        # AES-XTS data-unit handling incl. CTS
subtle = "2.6"                          # constant-time comparisons

# --- Memory hygiene ---
zeroize = { version = "1.8", features = ["zeroize_derive"] }
rand_core = "0.6"

# --- Parallelism / streaming / archive ---
rayon = "1.10"
zstd = "0.13"
tar = "0.4"
memmap2 = "0.9"

# --- Errors ---
thiserror = "2.0"
anyhow = "1.0"                          # FRB maps anyhow::Error -> Dart exception

# --- Platform raw I/O + memory locking ---
[target.'cfg(unix)'.dependencies]
nix = { version = "0.29", features = ["mman", "ioctl", "fs"] }
libc = "0.2"

[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.59", features = [
  "Win32_Foundation",
  "Win32_Security",
  "Win32_System_Memory",            # VirtualLock / VirtualUnlock
  "Win32_System_IO",
  "Win32_Storage_FileSystem",       # raw volume handles
  "Win32_System_Ioctl",             # IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
] }

# --- Hardware anchoring (Linux TPM 2.0) ---
[target.'cfg(target_os = "linux")'.dependencies]
tss-esapi = { version = "7.6", optional = true }   # ⚠ VERIFY version + system tpm2-tss dep

[features]
default = ["tpm"]
tpm = ["dep:tss-esapi"]
mldsa-purerust = ["dep:fips204"]     # toggle if AWS-LC lacks ML-DSA at pin time
fips = []                            # build/select the FIPS module (see §6.4)

[build-dependencies]
flutter_rust_bridge_codegen = "=2.7.0"   # optional: only if generating in build.rs
```

### 5.3 `hook/build.dart` — Native Assets fetch + verify + link (current API)

> Verified against `dart-lang/native`: `package:hooks` `build(args, (BuildInput,
> BuildOutputBuilder))`, `input.config.code.targetOS/targetArchitecture`,
> `os.dylibFileName(...)`, `output.assets.code.add(CodeAsset(...))`.
>
> **Supply-chain hardening (the part naive designs get wrong):** SHA-256 verification is
> meaningless if you fetch the *expected* hash from the *same* server that served the binary.
> The expected hashes are therefore **pinned in this source file** and updated per release
> by CI. A compromised release host cannot swap a binary without a source change.
>
> **Fallback contract:** on *any* error the hook **must not throw** — it emits no code asset
> and returns. The runtime selector (§5.5) then loads the pure-Dart backend. Never fail the
> end-user's build because a binary could not be fetched.

```dart
// hook/build.dart
import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:crypto/crypto.dart' show sha256;
import 'package:hooks/hooks.dart';
import 'package:http/http.dart' as http;

/// Release whose artifacts these pinned hashes correspond to.
const String _kReleaseTag = 'v0.1.0';
const String _kBaseUrl =
    'https://github.com/turkananation/pqforge_ffi/releases/download';

/// Pinned SHA-256 of every artifact (lowercase hex). Updated by CI per release.
/// THIS is the trust anchor — not a hash downloaded at build time.
const Map<String, String> _kPinnedSha256 = {
  'linux_x64':     '0000000000000000000000000000000000000000000000000000000000000000',
  'linux_arm64':   '0000000000000000000000000000000000000000000000000000000000000000',
  'macos_x64':     '0000000000000000000000000000000000000000000000000000000000000000',
  'macos_arm64':   '0000000000000000000000000000000000000000000000000000000000000000',
  'windows_x64':   '0000000000000000000000000000000000000000000000000000000000000000',
  'android_arm64': '0000000000000000000000000000000000000000000000000000000000000000',
  'android_arm':   '0000000000000000000000000000000000000000000000000000000000000000',
  'android_x64':   '0000000000000000000000000000000000000000000000000000000000000000',
  // iOS is delivered via the xcframework in the Flutter build, not this hook.
};

void main(List<String> args) async {
  await build(args, (BuildInput input, BuildOutputBuilder output) async {
    if (!input.config.buildCodeAssets) return;

    final code = input.config.code;
    final os = code.targetOS;
    final arch = code.targetArchitecture;

    try {
      final key = _targetKey(os, arch);
      final expected = _kPinnedSha256[key];
      if (expected == null || expected.startsWith('0000')) {
        throw _HookSkip('no pinned binary for target "$key"');
      }

      // Artifact name convention emitted by .github/workflows/release.yml.
      final ext = _archiveExt(os);
      final assetFile = 'pqforge_ffi-$key.$ext';
      final url = Uri.parse('$_kBaseUrl/$_kReleaseTag/$assetFile');

      // Content-addressed cache in the shared (cross-config) output dir.
      final cacheUri = input.outputDirectoryShared
          .resolve('pqforge_ffi/$_kReleaseTag/$key-$expected/');
      Directory.fromUri(cacheUri).createSync(recursive: true);

      final libFileName = os.dylibFileName('pqforge_ffi'); // libpqforge_ffi.so | .dylib | .dll
      final cachedLibUri = cacheUri.resolve(libFileName);
      final cachedLib = File.fromUri(cachedLibUri);

      if (!cachedLib.existsSync()) {
        final bytes = await _fetch(url);
        final digest = sha256.convert(bytes).toString();
        if (digest != expected) {
          throw _HookSkip(
              'SHA-256 mismatch for $assetFile (got $digest, want $expected)');
        }
        // Artifacts are shipped as raw shared libs in this convention; if you
        // ship compressed archives, decompress into cachedLib here instead.
        cachedLib.writeAsBytesSync(bytes, flush: true);
      }

      // Stage into this config's output dir for bundling.
      final outLibUri = input.outputDirectory.resolve(libFileName);
      cachedLib.copySync(File.fromUri(outLibUri).path);

      output.assets.code.add(
        CodeAsset(
          package: input.packageName,
          name: 'pqforge_ffi.dart', // bound as package:pqforge_ffi/pqforge_ffi.dart
          linkMode: DynamicLoadingBundled(),
          file: outLibUri,
        ),
      );

      // Re-run the hook if the pinned manifest (this file) changes.
      output.dependencies.add(input.packageRoot.resolve('hook/build.dart'));
    } on Object catch (e) {
      // CRITICAL: degrade, do not fail the build. No asset -> runtime fallback.
      stderr.writeln('[pqforge_ffi] native binary unavailable for '
          '${os.name}/${arch.name}; using pure-Dart fallback. Reason: $e');
      // Intentionally no rethrow and no asset emitted.
    }
  });
}

String _targetKey(OS os, Architecture arch) {
  String a;
  if (arch == Architecture.x64) {
    a = 'x64';
  } else if (arch == Architecture.arm64) {
    a = 'arm64';
  } else if (arch == Architecture.arm) {
    a = 'arm';
  } else {
    throw _HookSkip('unsupported architecture ${arch.name}');
  }
  if (os == OS.linux) return 'linux_$a';
  if (os == OS.macOS) return 'macos_$a';
  if (os == OS.windows) return 'windows_$a';
  if (os == OS.android) return 'android_$a';
  throw _HookSkip('unsupported OS ${os.name}');
}

String _archiveExt(OS os) {
  if (os == OS.windows) return 'dll';
  if (os == OS.macOS) return 'dylib';
  return 'so';
}

Future<List<int>> _fetch(Uri url) async {
  final res = await http
      .get(url)
      .timeout(const Duration(seconds: 30)); // air-gapped/proxy -> times out -> fallback
  if (res.statusCode != 200) {
    throw _HookSkip('HTTP ${res.statusCode} fetching $url');
  }
  return res.bodyBytes;
}

class _HookSkip implements Exception {
  _HookSkip(this.message);
  final String message;
  @override
  String toString() => 'HookSkip: $message';
}
```

### 5.4 `lib/src/backend/backend.dart` — the contract

```dart
import 'dart:typed_data';

/// Identifies which implementation answered a call (for diagnostics + tests).
enum BackendKind { native, fallback }

/// The single contract both the FRB-native and pure-Dart backends satisfy.
///
/// Every method is total: it either returns a value or throws a
/// [PqForgeException] subtype (see model/errors.dart). No method may return a
/// partially-initialized secret.
abstract interface class PqForgeBackend {
  BackendKind get kind;

  // --- ML-KEM (FIPS 203) ---
  Future<KemKeypair> kemGenerate(KemParams params);
  Future<KemEncapsulation> kemEncapsulate(Uint8List publicKey, KemParams params);
  Future<Uint8List> kemDecapsulate(
      Uint8List secretKey, Uint8List ciphertext, KemParams params);

  // --- ML-DSA (FIPS 204) ---
  Future<SignKeypair> signGenerate(SignParams params);
  Future<Uint8List> sign(Uint8List secretKey, Uint8List message, SignParams params);
  Future<bool> verify(
      Uint8List publicKey, Uint8List message, Uint8List signature, SignParams params);

  // --- Streaming AEAD + archive (Phase 3) ---
  Stream<ProgressEvent> packDirectory(PackRequest request);
  Stream<ProgressEvent> unpackArchive(UnpackRequest request);

  // --- ForgeFS volumes (Phase 4/5) ---
  Future<void> volumeFormat(VolumeFormatRequest request);
  Future<VolumeHandle> volumeUnlock(VolumeUnlockRequest request);
  Future<void> volumeDuressErase(String devicePath); // crypto-erase
}
```

### 5.5 `lib/src/backend/selector.dart` — probe + fallback selection

> The probe deliberately uses a cheap, side-effect-free native call
> (`pqforgeAbiVersion()`). If the native lib is absent (no asset bundled) or its ABI does not
> match, we fall back. Using FRB v2's runtime loader (try/catch around init) — rather than a
> static `@Native(assetId:)` binding — is what makes graceful degradation possible (§11-O1).

```dart
import 'package:logging/logging.dart';

import 'backend.dart';
import 'fallback_backend.dart';
import 'native_backend.dart';

final _log = Logger('pqforge_ffi.selector');

/// Expected native ABI. Bump when the Rust C-ABI surface changes.
const int kExpectedAbiVersion = 1;

class PqForgeBackends {
  PqForgeBackends._(this.active, {required this.reason});
  final PqForgeBackend active;
  final String reason;

  static PqForgeBackends? _instance;

  /// Resolve once; cache. Never throws — always yields a working backend.
  static Future<PqForgeBackends> resolve({bool forceFallback = false}) async {
    if (_instance != null) return _instance!;

    if (forceFallback) {
      _log.info('Forced pure-Dart fallback backend.');
      return _instance = PqForgeBackends._(FallbackBackend(), reason: 'forced');
    }

    try {
      final native = await NativeBackend.initialize(); // try/catch-able FRB init
      final abi = await native.abiVersion();
      if (abi != kExpectedAbiVersion) {
        throw StateError('ABI mismatch: native=$abi expected=$kExpectedAbiVersion');
      }
      _log.info('Native (FRB/AWS-LC) backend active. ABI=$abi');
      return _instance = PqForgeBackends._(native, reason: 'native abi=$abi');
    } on Object catch (e) {
      _log.warning('Native backend unavailable ($e); using pure-Dart fallback.');
      return _instance = PqForgeBackends._(FallbackBackend(), reason: 'fallback: $e');
    }
  }
}
```

### 5.6 `rust/src/error.rs` — error taxonomy + FFI panic boundary

```rust
use thiserror::Error;

/// The single error type crossing the FFI boundary. FRB maps `Err(_)` to a Dart
/// exception; a `catch_unwind` guard (below) converts any panic into `Internal`
/// so a panic can NEVER unwind across FFI (which is UB).
#[derive(Debug, Error)]
pub enum PqForgeError {
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("invalid ciphertext or tag mismatch")]
    InvalidCiphertext,
    #[error("authentication/verification failed")]
    AuthFailed,
    #[error("unaligned buffer: len {len} not a multiple of sector {sector}")]
    Unaligned { len: usize, sector: usize },
    #[error("I/O error: {0}")]
    Io(String),
    #[error("device error: {0}")]
    Device(String),
    #[error("hardware anchor error: {0}")]
    Anchor(String),
    #[error("unsupported on this platform: {0}")]
    Unsupported(String),
    #[error("internal error (recovered from panic): {0}")]
    Internal(String),
}

pub type PqResult<T> = Result<T, PqForgeError>;

/// Wrap every raw `extern "C"` symbol body in this. (FRB-generated functions are
/// already panic-guarded by FRB; use this for the hand-written C-ABI probes and
/// the duress fast-path that must not rely on FRB.)
pub fn guard<T>(f: impl FnOnce() -> PqResult<T> + std::panic::UnwindSafe) -> PqResult<T> {
    match std::panic::catch_unwind(f) {
        Ok(r) => r,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_string());
            Err(PqForgeError::Internal(msg))
        }
    }
}

/// Stable C-ABI probe used by the Dart selector to confirm the lib is loadable.
#[no_mangle]
pub extern "C" fn pqforge_abi_version() -> u32 {
    1
}
```

### 5.7 `rust/src/secret.rs` — zeroizing + page locking

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{PqForgeError, PqResult};

/// Heap secret that is wiped on drop AND pinned out of swap while alive.
#[derive(ZeroizeOnDrop)]
pub struct PinnedSecret {
    bytes: Vec<u8>,
    #[zeroize(skip)]
    locked: bool,
}

impl PinnedSecret {
    pub fn new(len: usize) -> PqResult<Self> {
        let bytes = vec![0u8; len];
        let mut s = Self { bytes, locked: false };
        s.lock_pages()?;
        Ok(s)
    }

    pub fn from_slice(src: &[u8]) -> PqResult<Self> {
        let mut s = Self::new(src.len())?;
        s.bytes.copy_from_slice(src);
        Ok(s)
    }

    pub fn as_slice(&self) -> &[u8] { &self.bytes }
    pub fn as_mut_slice(&mut self) -> &mut [u8] { &mut self.bytes }

    #[cfg(unix)]
    fn lock_pages(&mut self) -> PqResult<()> {
        // mlock prevents swap; also disable core dumps so secrets don't land in one.
        // SAFETY: ptr/len describe a live, owned allocation.
        unsafe {
            let ret = libc::mlock(self.bytes.as_ptr().cast(), self.bytes.len());
            if ret != 0 {
                // RLIMIT_MEMLOCK may forbid this for unprivileged users; degrade,
                // do not fail — the ZeroizeOnDrop guarantee still holds.
                self.locked = false;
                return Ok(());
            }
            #[cfg(target_os = "linux")]
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
        self.locked = true;
        Ok(())
    }

    #[cfg(windows)]
    fn lock_pages(&mut self) -> PqResult<()> {
        use windows_sys::Win32::System::Memory::VirtualLock;
        // SAFETY: ptr/len describe a live, owned allocation.
        let ok = unsafe {
            VirtualLock(self.bytes.as_ptr() as _, self.bytes.len())
        };
        self.locked = ok != 0; // best-effort
        Ok(())
    }
}

impl Drop for PinnedSecret {
    fn drop(&mut self) {
        // ZeroizeOnDrop already wipes `bytes`; unlock pages first.
        if self.locked {
            #[cfg(unix)]
            unsafe { let _ = libc::munlock(self.bytes.as_ptr().cast(), self.bytes.len()); }
            #[cfg(windows)]
            unsafe {
                use windows_sys::Win32::System::Memory::VirtualUnlock;
                let _ = VirtualUnlock(self.bytes.as_ptr() as _, self.bytes.len());
            }
        }
    }
}
```

### 5.8 `rust/src/crypto/kem.rs` — ML-KEM via AWS-LC ⚠ VERIFY

```rust
// ⚠ VERIFY against aws-lc-rs at pin time: the `kem` module is exposed under the
// `unstable` feature; algorithm constants are ML_KEM_768 / ML_KEM_1024.
use aws_lc_rs::kem;

use crate::error::{PqForgeError, PqResult};
use crate::secret::PinnedSecret;

#[derive(Clone, Copy)]
pub enum MlKemLevel { MlKem768, MlKem1024 }

impl MlKemLevel {
    fn algo(self) -> &'static kem::Algorithm<kem::AlgorithmId> {
        match self {
            MlKemLevel::MlKem768 => &kem::ML_KEM_768,
            MlKemLevel::MlKem1024 => &kem::ML_KEM_1024,
        }
    }
}

pub struct KemKeypair {
    pub public_key: Vec<u8>,      // public — not secret
    pub secret_key: PinnedSecret, // decapsulation key — pinned + zeroized
}

pub fn generate(level: MlKemLevel) -> PqResult<KemKeypair> {
    let decaps = kem::DecapsulationKey::generate(level.algo())
        .map_err(|_| PqForgeError::InvalidKey("ML-KEM keygen failed".into()))?;
    let public = decaps
        .encapsulation_key()
        .and_then(|ek| ek.key_bytes())
        .map_err(|_| PqForgeError::InvalidKey("export public key failed".into()))?
        .as_ref()
        .to_vec();
    let secret_raw = decaps
        .key_bytes()
        .map_err(|_| PqForgeError::InvalidKey("export secret key failed".into()))?;
    let secret_key = PinnedSecret::from_slice(secret_raw.as_ref())?;
    Ok(KemKeypair { public_key: public, secret_key })
}

pub struct Encapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: PinnedSecret,
}

pub fn encapsulate(level: MlKemLevel, public_key: &[u8]) -> PqResult<Encapsulation> {
    let ek = kem::EncapsulationKey::new(level.algo(), public_key)
        .map_err(|_| PqForgeError::InvalidKey("bad ML-KEM public key".into()))?;
    let (ct, ss) = ek
        .encapsulate()
        .map_err(|_| PqForgeError::Internal("encapsulate failed".into()))?;
    Ok(Encapsulation {
        ciphertext: ct.as_ref().to_vec(),
        shared_secret: PinnedSecret::from_slice(ss.as_ref())?,
    })
}

pub fn decapsulate(level: MlKemLevel, secret_key: &[u8], ct: &[u8]) -> PqResult<PinnedSecret> {
    let dk = kem::DecapsulationKey::new(level.algo(), secret_key)
        .map_err(|_| PqForgeError::InvalidKey("bad ML-KEM secret key".into()))?;
    let ss = dk
        .decapsulate(ct.into())
        .map_err(|_| PqForgeError::InvalidCiphertext)?;
    PinnedSecret::from_slice(ss.as_ref())
}
```

### 5.9 `rust/src/disk/header.rs` — ForgeVolumeHeader (crypto-erase model)

See §6 for the binary layout. Key idea: **the VMK lives only inside AEAD-wrapped key-slots**;
destroying the slots is the crypto-erase.

```rust
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

pub const SECTOR0_LEN: usize = 4096;           // header occupies the first 4 KiB
pub const VMK_LEN: usize = 64;                 // 512-bit Volume Master Key
pub const KEYSLOT_COUNT: usize = 8;            // passwords / recovery keys
pub const SALT_LEN: usize = 32;

/// On-disk metadata, serialized then AEAD-sealed into a key-slot.
/// There is NO plaintext magic string: a slot is "ours" iff its AEAD tag verifies
/// under the password-derived key. This is what makes the header look random.
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub struct VolumeMetadata {
    pub version: u16,
    #[zeroize(skip)]
    pub cipher_id: u8,          // 1 = AES-256-XTS
    #[zeroize(skip)]
    pub sector_size: u32,       // 512 or 4096
    #[zeroize(skip)]
    pub data_offset: u64,       // first data sector (after header region)
    #[zeroize(skip)]
    pub data_sectors: u64,
    pub vmk: [u8; VMK_LEN],     // SECRET — wiped on drop
}

/// One key-slot: Argon2id(salt, password) -> KEK -> AES-256-GCM seal of VolumeMetadata.
#[derive(Serialize, Deserialize, Clone)]
pub struct KeySlot {
    pub active: bool,
    pub salt: [u8; SALT_LEN],
    pub argon2_m_cost: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
    pub nonce: [u8; 12],
    pub ct_and_tag: Vec<u8>,    // AEAD(VolumeMetadata)
}

/// CRYPTO-ERASE: overwrite all key-slots with CSPRNG bytes + flush. The VMK is then
/// unrecoverable on ANY media because it existed only inside these sealed slots.
/// (Compare correction C1: this does not rely on physical sector overwrite semantics.)
pub fn crypto_erase_slots(buf: &mut [u8; SECTOR0_LEN], rng: &mut impl rand_core::RngCore) {
    rng.fill_bytes(buf);   // whole header region -> indistinguishable random
}
```

### 5.10 `rust/src/disk/xts.rs` — rayon-parallel AES-256-XTS

```rust
use rayon::prelude::*;
use xts_mode::Xts128;
use aes::Aes256;
use aes::cipher::{KeyInit, generic_array::GenericArray};

use crate::error::{PqForgeError, PqResult};

/// XTS-AES-256 uses two AES-256 keys (key1 || key2) = 64 bytes, exactly the VMK width.
pub struct XtsVolume {
    xts: Xts128<Aes256>,
    sector_size: usize,
}

impl XtsVolume {
    pub fn new(vmk: &[u8; 64], sector_size: usize) -> PqResult<Self> {
        if sector_size != 512 && sector_size != 4096 {
            return Err(PqForgeError::Device(format!("bad sector size {sector_size}")));
        }
        let c1 = Aes256::new(GenericArray::from_slice(&vmk[..32]));
        let c2 = Aes256::new(GenericArray::from_slice(&vmk[32..]));
        Ok(Self { xts: Xts128::new(c1, c2), sector_size })
    }

    /// Encrypt a buffer of N whole sectors in parallel; tweak = absolute sector index.
    pub fn encrypt_region(&self, buf: &mut [u8], first_sector: u64) -> PqResult<()> {
        self.assert_aligned(buf.len())?;
        let ss = self.sector_size;
        buf.par_chunks_mut(ss).enumerate().for_each(|(i, sector)| {
            let tweak = (first_sector + i as u64).to_le_bytes();
            let mut t = [0u8; 16];
            t[..8].copy_from_slice(&tweak);
            self.xts.encrypt_sector(sector, t);
        });
        Ok(())
    }

    pub fn decrypt_region(&self, buf: &mut [u8], first_sector: u64) -> PqResult<()> {
        self.assert_aligned(buf.len())?;
        let ss = self.sector_size;
        buf.par_chunks_mut(ss).enumerate().for_each(|(i, sector)| {
            let tweak = (first_sector + i as u64).to_le_bytes();
            let mut t = [0u8; 16];
            t[..8].copy_from_slice(&tweak);
            self.xts.decrypt_sector(sector, t);
        });
        Ok(())
    }

    fn assert_aligned(&self, len: usize) -> PqResult<()> {
        if len % self.sector_size != 0 {
            return Err(PqForgeError::Unaligned { len, sector: self.sector_size });
        }
        Ok(())
    }
}
```

### 5.11 `rust/src/disk/duress.rs` — crypto-erase fast path

```rust
use crate::disk::blockdev::BlockDevice;
use crate::disk::header::{crypto_erase_slots, SECTOR0_LEN};
use crate::error::PqResult;

/// Duress trigger: destroy the key-slots and flush durably. This bypasses normal
/// error handling — every step is best-effort and we still flush. We crypto-erase
/// the slots (correction C1) rather than pretending a plaintext wipe is instant.
///
/// If a hardware anchor was used (TPM/Enclave), also evict the sealed object so the
/// second wrapping layer is gone too (see anchor::evict).
pub fn duress_crypto_erase(dev: &mut BlockDevice) -> PqResult<()> {
    let mut header = [0u8; SECTOR0_LEN];
    let mut rng = aws_lc_rng();
    crypto_erase_slots(&mut header, &mut rng);

    // Write the randomized header region and force it to stable storage.
    dev.write_aligned(0, &header)?;
    dev.flush_durable()?; // fsync + FUA where available
    #[cfg(feature = "tpm")]
    let _ = crate::anchor::tpm::evict_sealed();
    Ok(())
}

fn aws_lc_rng() -> impl rand_core::RngCore {
    // Wrap aws_lc_rs::rand::SystemRandom behind a RngCore shim. ⚠ VERIFY shim at impl time.
    crate::crypto::SecureRng::default()
}
```

### 5.12 `lib/src/backend/fallback_backend.dart` — pure-Dart polyfill

```dart
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart' as pq; // the existing PointyCastle-based toolkit

import 'backend.dart';
import '../model/errors.dart';

/// Pure-Dart implementation. Slower + no hardware acceleration, but identical API
/// and identical wire format, so a volume/envelope made by the native backend
/// decrypts here and vice versa. ForgeFS raw-device ops are NOT available here
/// (they require the native layer) and throw [UnsupportedBackendException].
class FallbackBackend implements PqForgeBackend {
  @override
  BackendKind get kind => BackendKind.fallback;

  @override
  Future<KemKeypair> kemGenerate(KemParams params) async =>
      _adapt(() => pq.MlKem(params.level).generateKeyPair());

  // ... kemEncapsulate / kemDecapsulate / sign / verify delegate to pqforge ...

  @override
  Future<void> volumeFormat(VolumeFormatRequest request) async =>
      throw const UnsupportedBackendException(
          'ForgeFS volume formatting requires the native backend.');

  @override
  Future<void> volumeDuressErase(String devicePath) async =>
      throw const UnsupportedBackendException(
          'Duress crypto-erase requires the native backend.');

  T _adapt<T>(T Function() body) {
    try {
      return body();
    } on Object catch (e) {
      throw PqForgeException.fromFallback(e);
    }
  }
}
```

### 5.13 `.github/workflows/release.yml` — cross-compilation matrix

```yaml
name: release
on:
  push:
    tags: ['v*']
  workflow_dispatch:

permissions:
  contents: write   # create the GitHub Release + upload assets

jobs:
  # ---------------------------------------------------------------- Linux + Android
  linux:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu
      - name: aarch64 cross linker
        run: |
          sudo apt-get update
          sudo apt-get install -y gcc-aarch64-linux-gnu
      - name: Build Linux x86_64
        working-directory: rust
        run: cargo build --release --target x86_64-unknown-linux-gnu
      - name: Build Linux aarch64
        working-directory: rust
        env:
          CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER: aarch64-linux-gnu-gcc
        run: cargo build --release --target aarch64-unknown-linux-gnu
      - name: Android NDK build (cargo-ndk)
        working-directory: rust
        run: |
          cargo install cargo-ndk
          rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
          cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o ./jniLibs build --release
      - name: Stage artifacts
        run: |
          mkdir -p dist
          cp rust/target/x86_64-unknown-linux-gnu/release/libpqforge_core.so  dist/pqforge_ffi-linux_x64.so
          cp rust/target/aarch64-unknown-linux-gnu/release/libpqforge_core.so dist/pqforge_ffi-linux_arm64.so
          cp rust/jniLibs/arm64-v8a/libpqforge_core.so   dist/pqforge_ffi-android_arm64.so
          cp rust/jniLibs/armeabi-v7a/libpqforge_core.so dist/pqforge_ffi-android_arm.so
          cp rust/jniLibs/x86_64/libpqforge_core.so      dist/pqforge_ffi-android_x64.so
      - uses: actions/upload-artifact@v4
        with: { name: linux, path: dist/* }

  # ---------------------------------------------------------------- macOS + iOS
  macos:
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: >-
            x86_64-apple-darwin,aarch64-apple-darwin,
            aarch64-apple-ios,aarch64-apple-ios-sim,x86_64-apple-ios
      - name: Build macOS (universal dylib)
        working-directory: rust
        run: |
          cargo build --release --target x86_64-apple-darwin
          cargo build --release --target aarch64-apple-darwin
          mkdir -p ../dist
          lipo -create \
            target/x86_64-apple-darwin/release/libpqforge_core.dylib \
            target/aarch64-apple-darwin/release/libpqforge_core.dylib \
            -output ../dist/pqforge_ffi-macos_universal.dylib
          cp ../dist/pqforge_ffi-macos_universal.dylib ../dist/pqforge_ffi-macos_x64.dylib
          cp ../dist/pqforge_ffi-macos_universal.dylib ../dist/pqforge_ffi-macos_arm64.dylib
      - name: Build iOS xcframework (static libs)
        working-directory: rust
        run: |
          cargo build --release --target aarch64-apple-ios
          cargo build --release --target aarch64-apple-ios-sim
          cargo build --release --target x86_64-apple-ios
          # Combine the two simulator slices into one fat static lib.
          lipo -create \
            target/aarch64-apple-ios-sim/release/libpqforge_core.a \
            target/x86_64-apple-ios/release/libpqforge_core.a \
            -output /tmp/libpqforge_core-sim.a
          xcodebuild -create-xcframework \
            -library target/aarch64-apple-ios/release/libpqforge_core.a \
            -library /tmp/libpqforge_core-sim.a \
            -output ../dist/pqforge_ffi.xcframework
      - uses: actions/upload-artifact@v4
        with: { name: macos, path: dist/* }

  # ---------------------------------------------------------------- Windows
  windows:
    runs-on: windows-2022
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { targets: x86_64-pc-windows-msvc }
      - name: Build Windows x86_64
        working-directory: rust
        run: cargo build --release --target x86_64-pc-windows-msvc
      - name: Stage
        run: |
          mkdir dist
          copy rust\target\x86_64-pc-windows-msvc\release\pqforge_core.dll dist\pqforge_ffi-windows_x64.dll
      - uses: actions/upload-artifact@v4
        with: { name: windows, path: dist/* }

  # ---------------------------------------------------------------- Collect + hash + release
  release:
    needs: [linux, macos, windows]
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/download-artifact@v4
        with: { path: all }
      - name: Flatten + manifest of SHA-256
        run: |
          mkdir release
          find all -type f -exec cp {} release/ \;
          cd release
          : > manifest.json
          echo '{' >> manifest.json
          first=1
          for f in *; do
            [ "$f" = manifest.json ] && continue
            h=$(sha256sum "$f" | awk '{print $1}')
            [ $first -eq 0 ] && echo ',' >> manifest.json
            printf '  "%s": "%s"' "$f" "$h" >> manifest.json
            first=0
          done
          echo '' >> manifest.json
          echo '}' >> manifest.json
          cat manifest.json
      # NOTE: copy these hashes into hook/build.dart `_kPinnedSha256` and commit BEFORE
      # tagging the consumer release, so the trust anchor lives in source, not the server.
      - uses: softprops/action-gh-release@v2
        with:
          files: release/*
```

---

## 6. ForgeVolumeHeader binary layout

Sector 0 (first 4096 bytes) — **no plaintext magic** (deniability). Validity is proven by an
AEAD tag verifying under a password-derived key, not by a recognizable marker.

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0 | 32 | `outer_salt` | Argon2id salt for the outer/decoy volume; random ⇒ indistinguishable |
| 32 | 16 | `argon2_params` | m_cost, t_cost, p_cost, lanes (packed) |
| 48 | `8 × 240` | `keyslots[0..8]` | each: `active`, `nonce[12]`, `AES-256-GCM(VolumeMetadata)` |
| 1968 | 80 | reserved | random-filled |
| 2048 | 2048 | `hidden_header` | second AEAD region; only meaningful under Password Beta; otherwise CSPRNG noise |

- **VolumeMetadata** (sealed inside a key-slot) carries `version, cipher_id, sector_size,
  data_offset, data_sectors, vmk[64]`.
- **Unlock (outer / Password Alpha):** Argon2id(`outer_salt`, pw) → KEK → try to AEAD-open
  each active slot → on success, recover `vmk` → derive XTS keys via HKDF(`vmk`) → map data
  region at `data_offset`.
- **Unlock (hidden / Password Beta):** derive the hidden header location + key from Password
  Beta; AEAD-open the `hidden_header`; its `data_offset` points *inside* the outer volume's
  free space. Writing to the outer volume can overwrite the hidden one — this is the
  documented deniability trade-off (§7.3), identical to VeraCrypt's model.
- **Crypto-erase (duress):** overwrite bytes `0..4096` with CSPRNG and flush durably. Every
  key-slot (the only home of the VMK) is destroyed ⇒ unrecoverable on any media.

### 6.4 FIPS posture & the dual-profile model (correction C3)

The engine ships **two caller-selectable profiles** over one KEM-DEM/STREAM core (full suite in
§8.2):

- **`Profile::FipsStrict`** — built with `--features fips` (AWS-LC `aws-lc-fips-sys`), power-on
  self-tests, approved DRBG, and **only approved algorithms**: AES-256-GCM, ECDH P-256,
  ML-KEM-768/1024, ML-DSA-65/87, HKDF-SHA-256/384. It **refuses** ChaCha20-Poly1305, X25519 and
  AEGIS-256 at construction (those are outside the approved boundary — see §11-O8).
- **`Profile::MaxSpeed`** — default AWS-LC build; may add ChaCha20-Poly1305, X25519, and
  AEGIS-256 (if exposed) for raw throughput.

- Claim discipline: the strict profile is described as **"inside the boundary of a FIPS
  140-3-validated module (AWS-LC)"** — a statement about the *dependency*, never a claim that
  *this package* is itself validated. The fast profile is described as **"FIPS-aligned, not
  validated."** Any deployment needing certification must validate the specific build + boundary
  itself.

---

## 7. Security & threat model

### 7.1 What the native layer owns

- All long-lived key material, shared secrets, KEKs, and scratch buffers live in Rust
  `PinnedSecret`s: `mlock`/`VirtualLock`-pinned, `ZeroizeOnDrop`-wiped, never handed to the
  Dart GC as plaintext.
- Constant-time comparisons (`subtle`) for tags and secret equality.

### 7.2 Crypto-erase duress (the chosen model)

- The VMK exists only inside AEAD key-slots wrapped by Argon2id-derived KEKs (and optionally
  a TPM/Enclave-sealed second layer). Destroying the slots is instantaneous and
  media-independent. We additionally evict the sealed anchor object.
- We do **not** claim "< 2 ms, unrecoverable" for plaintext sectors — see C1.

### 7.3 Deniability — honest scope

- **Provided:** outer free space and the hidden header are AEAD ciphertext / CSPRNG,
  statistically indistinguishable from random; without Password Beta, the hidden volume's
  *existence* cannot be proven from the disk image alone.
- **NOT provided / documented limitations:** OS-level artifacts (hibernation, swap,
  prefetch/Spotlight, journals, MRU lists), filesystem metadata, controller wear-levelling,
  and repeated-snapshot diffing can all leak the existence or contents of a hidden volume.
  Coercion over time defeats any deniability scheme. Users are told this in plain language.

### 7.4 Supply chain

- Prebuilt binaries are SHA-256-pinned **in source** (§5.3); the release server is untrusted.
- Reproducible-ish builds via pinned toolchain (`rust-toolchain.toml`) + `Cargo.lock`.
- Optional: sign artifacts (minisign/cosign) and verify the signature in the hook as a second
  factor (future work).

---

## 8. Performance & TB-scale data path

> This section is the throughput core. The goal is "fastest possible PQ-hybrid FIPS-aligned
> engine at terabyte scale" — a *disk-bound, parallel, pipelined* problem, not the sequential
> 64 KB loop an earlier draft implied.

### 8.1 Throughput model (why the design is what it is)

AES-256-GCM with AES-NI runs ~1.5–4 GB/s **per core**. NVMe Gen4 ≈ 7 GB/s, Gen5 ≈ 14 GB/s. A
single crypto thread therefore **cannot saturate the disk** — so the engine spreads AEAD across
all cores and overlaps it with I/O. The target is to be **I/O-bound**: end-to-end throughput
within a small margin of raw sequential read/write bandwidth.

### 8.2 Dual-profile cipher suite (selected design)

Two caller-selectable profiles share one KEM-DEM / STREAM core; only the primitives differ.

| Concern | `Profile::FipsStrict` | `Profile::MaxSpeed` |
|---|---|---|
| Module | aws-lc **FIPS** build, approved mode + self-tests | aws-lc default build |
| Bulk AEAD | AES-256-GCM (VAES/AES-NI) | AES-256-GCM, or **AEGIS-256** / ChaCha20-Poly1305\* |
| Classical half of hybrid | ECDH **P-256** | **X25519** |
| PQ KEM / signature | ML-KEM-768/1024, ML-DSA-65/87 | same |
| DRBG | approved CTR_DRBG | system RNG |
| Claim | "inside a FIPS-validated module's boundary" | "FIPS-aligned, not validated" |

\*ChaCha20-Poly1305, X25519 and AEGIS-256 are **not** in the FIPS approved boundary — the strict
profile refuses them at construction time (see §11-O8). AEGIS-256 is enabled only if the pinned
`aws-lc-rs` exposes it; otherwise MaxSpeed uses VAES-accelerated AES-256-GCM.

### 8.3 Parallel chunked STREAM AEAD (replaces "one big GCM")

A single AES-GCM invocation is only safe for ~64 GiB per (key, nonce) — the 32-bit block counter
wraps — so "GCM over the whole file" is **incorrect** at TB scale. Instead the payload is split
into fixed frames (default 1 MiB) and each frame is sealed independently, **in parallel across
cores**, in an STREAM-style construction:

- One random 256-bit **DEK** per object (never the password/VMK directly).
- Per-frame nonce = `file_salt(8B) || frame_counter(u32, big-endian)` — deterministic, unique,
  no per-frame CSPRNG draw.
- The **final** frame carries a distinct flag in its AAD, defeating truncation/extension.
- A 4 KiB **authenticated header** (profile, alg IDs, frame size, file_salt, DEK commitment,
  recipient table) is the **AAD bound into every frame** — kills downgrade / parameter-confusion
  and cross-file splice attacks.
- **Key commitment:** the header commits to the DEK (GCM/Poly1305 are not key-committing),
  closing partitioning-oracle attacks on multi-recipient objects.

| On-disk field | Size | Notes |
|---|---|---|
| `magic` | 8 | format id |
| `header` | 4096 | AEAD-authenticated; AAD for every frame; DEK commitment + recipient table |
| `frame[i].ct` | `frame_size` | AES-256-GCM / AEGIS-256 / ChaCha20-Poly1305 |
| `frame[i].tag` | 16 | per-frame tag; last frame flagged in AAD |

```rust
// Frames encrypted in parallel, written in counter order.
fn frame_nonce(file_salt: [u8; 8], counter: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&file_salt);
    n[8..].copy_from_slice(&counter.to_be_bytes());
    n
}
fn frame_aad(header_hash: &[u8; 32], counter: u32, last: bool) -> Vec<u8> {
    let mut aad = header_hash.to_vec();        // binds the whole authenticated header
    aad.extend_from_slice(&counter.to_be_bytes());
    aad.push(last as u8);                       // truncation/extension defense
    aad
}
```

### 8.4 The I/O pipeline (replaces the 64 KB mmap loop)

64 KB ⇒ ~16M syscalls/TB and mmap thrashes the page cache on huge files. The big-file path is a
bounded, overlapping pipeline:

```text
reader(s) ──ring──▶ crypto pool (rayon, N frames in flight) ──ring──▶ ordered writer
```

- **1–4 MiB** aligned I/O units; **O_DIRECT** (Linux, ideally `io_uring`), **overlapped /
  `FILE_FLAG_NO_BUFFERING`** (Windows), **`F_NOCACHE`** (macOS) to bypass the page cache.
- **Bounded channels** give backpressure: a slow disk stalls producers instead of growing RAM.
- A small **reorder buffer** lets frames finish out of order but be written in counter order.
- `memmap2` is retained only for the *many-small-files* directory path, not big files.

### 8.5 Multi-recipient = encrypt the payload once

Encrypt the TB **once** under the random DEK; then for each recipient ML-KEM-encapsulate and
AEAD-wrap only the 32-byte DEK (rayon over the cheap wraps). Never re-encrypt the payload per
recipient. The recipient table lives in the authenticated header.

### 8.6 Adaptive compression

`zstd → tar → AEAD` is correct ordering (compress before encrypt) but wastes CPU and caps
throughput on incompressible inputs (media, already-encrypted blobs). The engine **samples**
each input and **skips** compression when the ratio is poor; otherwise it uses **multithreaded
zstd** (`nbWorkers`) — or **lz4** when the goal is max GB/s over ratio. Whether a frame is
compressed is recorded in the header, never assumed.

### 8.7 Hybrid combiner (correction to the earlier "XOR" note)

"XOR or concatenate the shared secrets" is **not** a safe combiner. The engine uses an
SP 800-56C-style concat-KDF with **transcript binding**:
`key = HKDF(salt, ss_pq || ss_classical || H(kem_ct || classical_pub || header), info)`, so
neither shared secret can be re-encapsulated independently. Hash = SHA-256/384 (approved in both
profiles).

### 8.8 TB-scale operational edges

- **Resumable:** periodic checkpoint of `{frame_counter, bytes_done}` lets a killed multi-hour
  job resume instead of restarting.
- **Atomic output:** temp file → `fsync` → `rename`; an interrupted run never leaves a corrupt
  file that authenticates as valid.
- **Bad-block policy:** a read/write error is a typed `PqForgeError`, never a panic; the partial
  output (temp file) is unlinked.
- **Bounded memory:** sustained TB throughput holds RSS flat via the bounded pipeline.

### 8.9 Hardware acceleration

AWS-LC runtime-dispatches AES-NI / **VAES** (AVX-512, 2–4× on recent x86) / ARMv8 Crypto
Extensions, and AVX2/NEON for ML-KEM/ML-DSA. CI must **not** pin conservative `target-feature`
flags that disable these paths; both XTS and GCM benefit from VAES.

---

## 9. Public Dart API sketch

```dart
final pq = await PqForge.instance();        // resolves native|fallback once
final kp = await pq.kem.generate(MlKem.level768);
final enc = await pq.kem.encapsulate(kp.publicKey);
final ss = await pq.kem.decapsulate(kp.secretKey, enc.ciphertext);

await pq.volume.format(VolumeFormatRequest(
  devicePath: '/dev/sdX', password: alpha, hiddenPassword: beta, sectorSize: 4096,
));
final vol = await pq.volume.unlock(VolumeUnlockRequest(devicePath: '/dev/sdX', password: alpha));
await pq.volume.duressErase('/dev/sdX');    // crypto-erase

print(pq.backend.kind); // BackendKind.native or .fallback
```

---

## 10. Testing strategy

- **KATs:** FIPS 203 / 204 known-answer vectors gate every release (P2).
- **Cross-backend equivalence:** the same envelope/volume produced natively must open in the
  pure-Dart fallback and vice-versa.
- **Fallback-present-absent:** CI runs the suite once with the native lib bundled and once
  with it removed; both must pass.
- **Loopback volume tests:** `losetup` (Linux) / VHD (Windows) round-trip incl. unaligned-write
  rejection and header-tamper detection.
- **Memory:** valgrind/ASan confirms secrets zeroed; a `mlock` audit confirms no secret pages
  are swappable.
- **Fuzzing:** `cargo fuzz` on header parsing and AEAD framing.
- **Throughput benchmarks:** `criterion` micro-benchmarks (GB/s per primitive) + an end-to-end
  TB harness; a CI **perf-regression gate** fails the build on a >X% throughput drop; publish a
  GB/s-per-platform table. *(You cannot claim "fastest" without measuring it — P3.5 DoD.)*
- **Disk-bound check:** big-file encrypt throughput stays within ~Y% of raw sequential read
  bandwidth (i.e. the engine is I/O-bound, not CPU-bound) on an NVMe target.
- **Crash/resume:** `kill -9` mid-TB encryption, then resume from checkpoint and verify bit-exact
  output; the atomic temp→rename path never exposes a corrupt-but-authenticating file.
- **STREAM framing attacks:** truncation, frame-reorder, and cross-file splice attempts all fail
  authentication.
- **Profile conformance:** `Profile::FipsStrict` refuses every non-approved algorithm
  (ChaCha20-Poly1305 / X25519 / AEGIS-256); `Profile::MaxSpeed` round-trips with them.

---

## 11. Open items to verify at implementation time (no-hallucination ledger)

These are the spots where I will confirm the live API/behavior before writing the real code,
rather than assert it now:

- **O1 — Native Assets activation + FRB loader handshake.** The build-hook protocol packages
  (`hooks`, `code_assets`) and the SDK opt-in flag name are version-dependent; and the exact
  way FRB v2's runtime loader consumes a `DynamicLoadingBundled` `CodeAsset` (vs a static
  `@Native(assetId:)` binding) must be validated so the *fallback-on-absent* path works. The
  `build(args, (BuildInput, BuildOutputBuilder))` surface itself is **verified** (§5.3).
- **O2 — `aws-lc-rs` ML-DSA (FIPS 204).** Confirm whether the pinned `aws-lc-rs` exposes
  ML-DSA in its public Rust API. If not, build with `--features mldsa-purerust` (`fips204`
  crate) behind the same trait. ML-KEM via the `unstable` `kem` module is the expected path.
- **O3 — `tss-esapi` version + platform availability.** TPM 2.0 anchoring is Linux-first;
  Windows uses TBS, macOS/iOS use the Secure Enclave via a host-app platform channel (cannot
  be done purely in Rust because Enclave access needs the app's entitlements).
- **O4 — Block-device ioctls.** `BLKSSZGET`/`BLKGETSIZE64` (Linux), `DKIOCGETBLOCKSIZE`
  (macOS), `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX` (Windows) for sector probing.
- **O5 — iOS xcframework link mode.** Static-lib xcframework vs dynamic framework affects both
  `crate-type` and the consumer's Xcode integration; validate against a real Flutter iOS build.
- **O6 — FRB version lockstep.** `flutter_rust_bridge` (Dart) and `flutter_rust_bridge_codegen`
  (CLI/build-dep) must be the *same* version; pin both in CI.
- **O7 — `aws-lc-rs` AEAD nonce/streaming surface.** Confirm the explicit-nonce one-shot API
  for AES-256-GCM and ChaCha20-Poly1305 (and whether AEGIS-256 is exposed). TB-scale uses our
  own STREAM framing (§8.3) regardless of whether aws-lc offers an incremental API.
- **O8 — FIPS approved-service boundary.** Confirm which algorithms the pinned `aws-lc-fips`
  module lists as approved. Working assumption: ChaCha20-Poly1305 and X25519 are **outside** the
  boundary, so `Profile::FipsStrict` must reject them and use AES-256-GCM + ECDH P-256. AEGIS-256
  is non-FIPS (MaxSpeed only).
- **O9 — High-throughput I/O primitives.** `io_uring` (Linux ≥5.x) vs `O_DIRECT` alignment
  rules; Windows overlapped / IoRing; macOS `F_NOCACHE` — validate alignment + buffer-size
  constraints per platform before committing the pipeline (§8.4).
- **O10 — Hybrid combiner standard.** Pin the exact concat-KDF (SP 800-56C / IETF hybrid-KEM
  transcript binding, §8.7) and confirm HKDF + approved hash (SHA-256/384) in both profiles.

---

## 12. Implementation order

> **Moved to [`ROADMAP.md`](ROADMAP.md)** — see "Turn-by-turn implementation order."
