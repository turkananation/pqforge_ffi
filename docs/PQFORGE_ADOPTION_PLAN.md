# pqforge × pqforge_ffi — dependency and adoption plan

> **Status:** plan, **revision 3** (2026-09-18). Supersedes revision 2's
> dual-license (AGPL-3.0-only OR commercial) unification: `pqforge_ffi` is
> **MIT**, matching `pqforge`. The dependency arrow `pqforge → pqforge_ffi`
> remains **permitted**. Written against `pqforge_ffi` v0.1.0, whose GitHub
> release ships prebuilt native libraries
> (`libpqforge_core-linux-x86_64.so`, `-linux-aarch64.so`,
> `-macos-{aarch64,x86_64}.dylib`, `pqforge_core-windows-x86_64.dll`) plus a
> `SHA256SUMS` manifest, and `pqforge` 0.3.0 (MIT, on pub.dev). Companion to
> [`INTEGRATION_AND_HYBRID_PLAN.md`](INTEGRATION_AND_HYBRID_PLAN.md).

## 0. License strategy — one stack, one story

- **Both packages: MIT.** `pqforge_ffi` is MIT; `pqforge` already is. There is
  no dual license, no AGPL option, and no commercial-license track.
- **History stays honest.** `pqforge_ffi` briefly shipped under AGPL-3.0-only
  OR commercial at v0.1.0; that dual license is withdrawn. Current `main` and
  subsequent releases are MIT. `pqforge` has been MIT throughout.
- **Copyright hygiene.** Turkana Nation is sole author of both packages today;
  before accepting external PRs, add a short CONTRIBUTING note (inbound =
  outbound).
- **NOTICE** in `pqforge_ffi` records third-party components (AWS-LC,
  `aws-lc-rs`, zeroize, Dart deps). MIT is compatible with those licenses; no
  AGPL §7 linking exception is required.
- **Dependency-license check:** `pqforge`'s deps (pointycastle MIT,
  cryptography Apache-2.0, args/path/etc. BSD) are all permissive and
  MIT-compatible.

## 1. Dependency architecture — the arrow inverts

With the license unified there is no legal reason to keep `pqforge` ignorant
of its accelerator, and one strong product reason to invert:
**batteries-included acceleration** — `dart pub add pqforge` should be enough
for a user to get native speed when a verified library is present.

```text
 rev 1 (license-driven):   pqforge_ffi ──→ pqforge          (app wires providers)
 rev 2 (this plan):        pqforge 0.4.0 ──→ pqforge_ffi 0.2.0 ──→ pqforge (interfaces)
```

- **The cycle is deliberate and bounded.** `pqforge_ffi` needs `pqforge` for
  the provider interfaces and the pure-Dart fallback; `pqforge` 0.4.0 gains a
  dependency on `pqforge_ffi` for auto-registration. Pub's solver permits
  dependency cycles between hosted packages; both packages are released by one
  owner in lockstep, which is the one situation where a cycle is manageable.
- **Constraint rule for the cycle (normative — a naive `^` makes 0.4.0
  unresolvable).** If `pqforge_ffi` 0.2.0 shipped with `pqforge: ^0.3.0`
  (`>=0.3.0 <0.4.0`), any consumer of `pqforge` 0.4.0 would hit an immediate
  version-solving failure: the solver would need `pqforge` 0.4.0 and a
  `pqforge_ffi` that permits it, and none would exist. Therefore
  `pqforge_ffi`'s dependency on `pqforge` must **always span the partner's
  current and next minor** — 0.2.0 ships `pqforge: ">=0.3.0 <0.5.0"` — and
  every future `pqforge` minor bump is accompanied by a same-day
  `pqforge_ffi` point release that re-widens its range **before** the
  `pqforge` release is published.
  **First-publish order resolves the chicken-and-egg:** publish
  `pqforge_ffi` 0.2.0 to pub.dev first (its widened constraint resolves
  against the already-hosted 0.3.0), then `pqforge` 0.4.0 (depending on
  `pqforge_ffi ^0.2.0`).
- **Known costs of the cycle, and the triggers to abandon it.** Some
  workspace/graph tooling (melos, lakos, custom dependency linting) warns or
  fails on cycles, and the constraint rule above is recurring release
  overhead. The cycle stays plan-of-record (owner decision: one package, one
  story), but switch to the reserve architecture if any of these fire:
  pub.dev publish validation rejects the cycle; the repos adopt
  cycle-intolerant tooling; or the lockstep constraint dance causes a second
  botched release. **Reserve architecture:** a three-package DAG (`pqforge`
  core-with-interfaces ← `pqforge_ffi` ← thin `pqforge_accel` glue that ties
  them together), or equivalently a service-locator/bootstrapper package that
  registers providers without `pqforge` compile-depending on `pqforge_ffi`.
- **Prerequisite:** `pqforge_ffi` must be **published to pub.dev** (it is not
  today — v0.1.0 is a GitHub release only). It already carries a proper
  LICENSE; pub.dev accepts MIT-licensed packages.

### 1.1 What `pqforge` 0.4.0 does with the dependency

- **Respect the pure-barrel hard constraint.** `pqforge`'s AGENTS.md mandates
  that `package:pqforge/pqforge.dart` stays pure Dart / web-safe (no `dart:ffi`
  or `dart:io` in its transitive import graph). The `pqforge_ffi` dependency
  therefore attaches to a **separate entrypoint** — `pqforge_io.dart` or a new
  `package:pqforge/pqforge_accel.dart` — which is where auto-registration
  lives. Web and pure users import the main barrel and never touch FFI.
  AGENTS.md's "only sanctioned FFI is `tool/openssl_interop/`" rule must be
  amended in the same PR that adds the dependency.
- **Auto-registration:** at startup (lazily, on first crypto use, or via an
  explicit `PqAcceleration.enable()`), `pqforge` asks `pqforge_ffi` to locate
  a native library — `PQFORGE_NATIVE_LIB` env var first, then the
  **platform-standard cache directory** (Linux: `$XDG_CACHE_HOME/pqforge`
  falling back to `~/.cache/pqforge`; macOS: `~/Library/Caches/pqforge`;
  Windows: `%LOCALAPPDATA%\pqforge\cache` — never a hardcoded Unix path),
  under `native/<tag>/<asset>` — **verifies its SHA-256 against the checksum
  table baked into the package** (see §1.2), and
  registers `NativePqforgeLatticeProvider` + `NativePqforgeClassicalProvider`.
  Any failure → pure Dart, silently, exactly as today. Also
  `PqAcceleration.disable()` and a diagnostics getter (which engine served).
- **CLI:** `pqforge accelerate fetch` — downloads the right release asset for
  the current platform, verifies it against the **baked-in** checksums, and
  installs it into the cache path. Explicit user action, so it does not
  violate the no-silent-downloads rule (§4). `pqforge accelerate status`
  prints engine, library path, and hash.
- **Docs:** README gains a "Hardware acceleration" section — two lines to
  enable, where binaries come from, and the licensing statement from §0.

### 1.2 What `pqforge_ffi` 0.2.0 needs before that (publish gate)

- **Checksum-pinned loader:** `verifyAndOpen(path, sha256: …)` refusing to
  load a non-matching library, plus a generated `release_checksums.dart`
  (tag → asset → SHA-256 map, produced from `SHA256SUMS` at release time) so
  downstream verification never fetches a checksum over the network.
- **pub.dev publish readiness:** `dart pub publish --dry-run` clean;
  `.pubignore` for `rust/target`; keep the repo's Rust source in the package
  (source builds) but document that binaries come from GitHub releases; and
  the **widened `pqforge: ">=0.3.0 <0.5.0"` constraint** from §1's normative
  rule — this is a publish blocker, not a nice-to-have.
- Existing v0.1.0 surface is otherwise sufficient — the providers and
  fallback semantics are already proven (190 native-mode tests).

### 1.3 Seam work that survives from revision 1 (still required)

- **Freeze the provider seams** (`PqLatticeProvider`, `PqClassicalProvider`)
  as a versioned public contract; document which operations are
  byte-deterministic (kemDecapsulate, dsaVerify, seeded keygen, X25519 ECDH,
  Ed25519) versus randomized.
- **Export the conformance harnesses** as `package:pqforge/conformance.dart`
  (lattice + a new classical harness) so `pqforge_ffi` CI runs the upstream
  suite against the native providers on every commit.
- **AEAD engine seam** (`PqForgeEngine.provider`) in a later minor — lets the
  accelerator take AES-256-GCM / ChaCha20-Poly1305 (completes Phase β).
- **RNG note + test** that `PqRandom.generator` governs every random draw.

## 2. Relicensing — withdrawn

Revision 2 planned relicensing `pqforge` to AGPL-3.0-only OR commercial at
v0.4.0, copying `pqforge_ffi`'s dual-license files. That is **withdrawn**:
`pqforge_ffi` is MIT, `pqforge` stays MIT, and there is no
`COMMERCIAL-LICENSE.md`. v0.4.0 of `pqforge` is the acceleration-adoption
release only (dependency, auto-registration, CLI, conformance, seam freeze).

## 3. Sequencing

| Step | Package | Version | What |
| --- | --- | --- | --- |
| 1 (done) | pqforge_ffi | v0.1.0 | GitHub release with binaries + SHA256SUMS |
| 1b (done) | pqforge_ffi | — | Relicensed to MIT; dual AGPL/commercial dropped |
| 2 | pqforge_ffi | v0.2.0 | verified loader + baked checksums + pub.dev publish readiness → **publish to pub.dev** |
| 3 | pqforge | v0.4.0 | dependency on `pqforge_ffi ^0.2.0` + auto-registration + `accelerate` CLI + conformance export + seam freeze → publish |
| 4 | pqforge | v0.5.0 | AEAD engine seam + RNG guarantee (Phase β complete) |
| 5 | pqforge_ffi | v0.3.x | Native Assets (`hook/build.dart`) auto-build; mobile prebuilts |

## 4. Rules that still hold

- **No silent runtime downloads.** Fetching executable code is always an
  explicit action (`pqforge accelerate fetch`) or the app's own build/deploy
  step — never implicit inside a crypto call. Auto-*registration* of an
  already-present, checksum-verified library is fine; auto-*download* is not.
- **Checksums are pinned in source** (shipped in the package), never fetched
  at runtime — a fetched checksum verifies nothing.
- **The pure-Dart path remains a first-class, complete implementation** — the
  stack must stay fully functional (and fully tested) with no native library.
- **PFE1 standalone surface stays**, but the provider path is the primary
  integration story (Model B in
  [`INTEGRATION_AND_HYBRID_PLAN.md`](INTEGRATION_AND_HYBRID_PLAN.md)).
