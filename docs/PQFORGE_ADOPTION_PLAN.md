# What `pqforge` needs to consume `pqforge_ffi` v0.1.0

> **Status:** plan. Written at the v0.1.0 release of `pqforge_ffi`, whose GitHub
> release ships prebuilt native libraries (`libpqforge_core-linux-x86_64.so`,
> `-linux-aarch64.so`, `-macos-{aarch64,x86_64}.dylib`,
> `pqforge_core-windows-x86_64.dll`) plus a `SHA256SUMS` manifest. Companion to
> [`INTEGRATION_AND_HYBRID_PLAN.md`](INTEGRATION_AND_HYBRID_PLAN.md).

## 0. Ground rules (license interplay — read first)

- `pqforge` is MIT. `pqforge_ffi` (from v0.1.0) is **AGPL-3.0-only OR
  commercial**.
- Therefore `pqforge` must **never depend on `pqforge_ffi`** — not even as a
  dev/optional dependency. The dependency arrow stays exactly as it is today:
  `pqforge_ffi → pqforge`. Acceleration is opt-in by the **host application**,
  which registers the native providers through `pqforge`'s seams.
- An application that registers `pqforge_ffi`'s providers is combining its work
  with AGPL-licensed code: it must either be open source under AGPL-compatible
  terms or hold a commercial license. An application that uses plain `pqforge`
  is MIT-only, unencumbered. `pqforge`'s README must state this plainly so no
  adopter is surprised — that disclosure is itself one of the changes below.

## 1. Changes `pqforge` needs (ranked)

### 1.1 Freeze and version the provider seams (required)

`PqLatticeProvider` and `PqClassicalProvider` are now a **public ABI contract**
consumed by an out-of-repo accelerator. From `pqforge` 0.3.x onward:

- Treat any change to the provider interfaces (method signatures, added
  members, semantics of `seed`/`nonce`/`context`/`preHash`) as a **breaking
  change** requiring a major/minor version gate and a CHANGELOG callout.
- Document, on each provider method, which operations must be
  **byte-deterministic** (kemDecapsulate, dsaVerify, seeded keygen, X25519
  ECDH, Ed25519) versus randomized — this is the contract the accelerator's
  cross-implementation KATs pin.

### 1.2 Export the conformance harnesses (required)

`test/support/lattice_conformance.dart` lives in `pqforge`'s test tree, so an
external provider cannot import it. Add a public library, e.g.
`package:pqforge/conformance.dart`, exposing:

- the lattice conformance/agreement harness (existing);
- a **classical** conformance harness (X25519 agreement symmetry, Ed25519
  KAT/round-trip, tamper rejection) mirroring it.

Then `pqforge_ffi`'s CI can run the *upstream* conformance suite against the
native providers on every commit, instead of re-deriving it.

### 1.3 README "Hardware acceleration" section (required)

A short section in `pqforge`'s README:

- point to `pqforge_ffi` and the release-asset naming scheme;
- show the two-line registration (`PqLattice.provider = …`,
  `PqClassical.provider = …`);
- state the license interplay from §0 explicitly (MIT core, AGPL/commercial
  accelerator);
- instruct apps to **verify the downloaded library against `SHA256SUMS`
  before loading it** (see §2).

### 1.4 AEAD engine seam (next minor, enables Phase β)

`PqForgeEngineProvider` selects between built-in engines but has no seam for a
custom native engine. Add one (mirroring `PqLattice.provider`):
`PqForgeEngine.provider`, defaulting to the current selection logic. This lets
`pqforge_ffi` route AES-256-GCM / ChaCha20-Poly1305 through AWS-LC and closes
the largest remaining pure-Dart hot path after the lattice math.

### 1.5 RNG seam hardening (cheap, same minor as 1.4)

`PqRandom.generator` is already swappable. Add a doc note + test that a
registered generator is used by *every* random draw (keygen, encapsulation,
nonces), so a native FIPS DRBG can be registered with confidence.

### 1.6 Diagnostics surface (nice-to-have)

`PqLattice.provider.name` exists; add a tiny
`PqForge.diagnostics()` (active lattice/classical provider names + versions)
so applications can log what engine actually served them — useful when a
fleet mixes accelerated and fallback nodes.

## 2. How applications should fetch and pin the native library

`pub.dev` cannot ship the binary, so apps (not `pqforge`) fetch it:

1. Download the asset for the current platform from
   `https://github.com/turkananation/pqforge_ffi/releases/download/v0.1.0/<asset>`.
2. Verify its SHA-256 against the release's `SHA256SUMS` **pinned in the app's
   source** (not fetched at runtime — a fetched checksum verifies nothing).
3. Store under an app-controlled dir (e.g. `~/.cache/<app>/pqforge/<tag>/`).
4. Load by explicit path: `NativePqforgeLatticeProvider.open(path)` etc.
   Any failure (missing file, ABI mismatch, self-test) silently degrades to
   pure Dart — the app stays correct, just slower.

`pqforge_ffi` v0.2 candidates that make this smoother (tracked here, not in
`pqforge`): a `verifyAndOpen(path, sha256: …)` helper that refuses to load a
tampered library; a `tool/fetch_native.dart` consumers can vendor; Dart Native
Assets (`hook/build.dart`) auto-bundling, which removes the manual fetch
entirely for source builds.

## 3. Sequencing

| When | What |
| --- | --- |
| now (pqforge 0.3.x patch) | §1.3 README disclosure + §1.1 seam-freeze note |
| pqforge 0.3.x minor | §1.2 conformance export — unblocks upstream-verified CI here |
| pqforge 0.4.0 | §1.4 AEAD seam + §1.5 RNG note (Phase β complete) |
| pqforge_ffi v0.2 | checksum-verified loader + fetch tool; Native Assets spike |

## 4. Explicit non-goals

- No `pqforge → pqforge_ffi` dependency in any form (license, §0).
- No auto-download inside `pqforge` or `pqforge_ffi` at runtime — fetching
  executable code over the network belongs to the app's build/deploy step,
  under its own supply-chain controls.
- No divergence of the standalone `PFE1` surface: it stays, but the drop-in
  provider path is the primary integration story (Model B in
  [`INTEGRATION_AND_HYBRID_PLAN.md`](INTEGRATION_AND_HYBRID_PLAN.md)).
