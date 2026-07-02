import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:pqforge_ffi/pqforge_ffi.dart';
import 'package:test/test.dart';

// C-ABI signatures (mirror rust/crates/pqforge_core/src/crypto/kem.rs).
typedef _KeygenNative =
    Int32 Function(
      Int32,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
    );
typedef _KeygenDart =
    int Function(
      int,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
    );
typedef _EncapNative =
    Int32 Function(
      Int32,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
    );
typedef _EncapDart =
    int Function(
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
    );
typedef _DecapNative =
    Int32 Function(
      Int32,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
    );
typedef _DecapDart =
    int Function(
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
    );

String _libPath() {
  final name = Platform.isWindows
      ? 'pqforge_core.dll'
      : Platform.isMacOS
      ? 'libpqforge_core.dylib'
      : 'libpqforge_core.so';
  return '${Directory.current.path}/rust/target/release/$name';
}

Pointer<Uint8> _toNative(Uint8List data) {
  final p = calloc<Uint8>(data.isEmpty ? 1 : data.length);
  if (data.isNotEmpty) p.asTypedList(data.length).setAll(0, data);
  return p;
}

/// Thin Dart wrapper over the native ML-KEM C-ABI for the equivalence tests.
class _NativeKem {
  _NativeKem(DynamicLibrary lib)
    : _keygen = lib.lookupFunction<_KeygenNative, _KeygenDart>(
        'pqforge_mlkem_keygen',
      ),
      _encap = lib.lookupFunction<_EncapNative, _EncapDart>(
        'pqforge_mlkem_encapsulate',
      ),
      _decap = lib.lookupFunction<_DecapNative, _DecapDart>(
        'pqforge_mlkem_decapsulate',
      );

  final _KeygenDart _keygen;
  final _EncapDart _encap;
  final _DecapDart _decap;

  (Uint8List, Uint8List) keygen(PqKemAlgorithm alg) {
    final pk = calloc<Uint8>(alg.publicKeyBytes);
    final sk = calloc<Uint8>(alg.secretKeyBytes);
    final pl = calloc<Size>();
    final sl = calloc<Size>();
    try {
      _check(
        _keygen(
          alg.index,
          pk,
          alg.publicKeyBytes,
          pl,
          sk,
          alg.secretKeyBytes,
          sl,
        ),
      );
      return (
        Uint8List.fromList(pk.asTypedList(pl.value)),
        Uint8List.fromList(sk.asTypedList(sl.value)),
      );
    } finally {
      calloc
        ..free(pk)
        ..free(sk)
        ..free(pl)
        ..free(sl);
    }
  }

  (Uint8List, Uint8List) encapsulate(PqKemAlgorithm alg, Uint8List publicKey) {
    final pub = _toNative(publicKey);
    final ct = calloc<Uint8>(alg.ciphertextBytes);
    final ss = calloc<Uint8>(alg.sharedSecretBytes);
    final cl = calloc<Size>();
    final sl = calloc<Size>();
    try {
      _check(
        _encap(
          alg.index,
          pub,
          publicKey.length,
          ct,
          alg.ciphertextBytes,
          cl,
          ss,
          alg.sharedSecretBytes,
          sl,
        ),
      );
      return (
        Uint8List.fromList(ct.asTypedList(cl.value)),
        Uint8List.fromList(ss.asTypedList(sl.value)),
      );
    } finally {
      calloc
        ..free(pub)
        ..free(ct)
        ..free(ss)
        ..free(cl)
        ..free(sl);
    }
  }

  Uint8List decapsulate(
    PqKemAlgorithm alg,
    Uint8List secretKey,
    Uint8List ciphertext,
  ) {
    final sk = _toNative(secretKey);
    final ct = _toNative(ciphertext);
    final ss = calloc<Uint8>(alg.sharedSecretBytes);
    final sl = calloc<Size>();
    try {
      _check(
        _decap(
          alg.index,
          sk,
          secretKey.length,
          ct,
          ciphertext.length,
          ss,
          alg.sharedSecretBytes,
          sl,
        ),
      );
      return Uint8List.fromList(ss.asTypedList(sl.value));
    } finally {
      calloc
        ..free(sk)
        ..free(ct)
        ..free(ss)
        ..free(sl);
    }
  }

  void _check(int rc) {
    if (rc != PqForgeErrorCode.ok.value) {
      throw StateError(
        'native KEM failed: ${PqForgeErrorCode.fromValue(rc).name}',
      );
    }
  }
}

/// Phase 2.3 validation: the native AWS-LC ML-KEM and the pure-Dart `pqforge`
/// fallback must be byte-level interoperable (both implement FIPS 203). Skipped
/// cleanly if the native library is not built.
void main() {
  final libPath = _libPath();
  if (!File(libPath).existsSync()) {
    test(
      'native ML-KEM tests',
      () {},
      skip: 'native library not built at $libPath',
    );
    return;
  }

  late final _NativeKem native;
  const fallback = FallbackBackend();
  setUpAll(() => native = _NativeKem(DynamicLibrary.open(libPath)));

  for (final alg in PqKemAlgorithm.values) {
    test(
      '${alg.name}: native keygen → encapsulate → decapsulate round-trip',
      () {
        final (pk, sk) = native.keygen(alg);
        expect(pk.length, alg.publicKeyBytes);
        expect(sk.length, alg.secretKeyBytes);
        final (ct, ssEnc) = native.encapsulate(alg, pk);
        final ssDec = native.decapsulate(alg, sk, ct);
        expect(ssDec, equals(ssEnc));
      },
    );

    test(
      '${alg.name}: cross-backend — native key, pqforge encapsulate, native decapsulate',
      () {
        final (pk, sk) = native.keygen(alg);
        // pqforge (pure Dart) encapsulates to the native-generated public key…
        final enc = fallback.kemEncapsulate(alg, pk);
        // …and native (AWS-LC) decapsulates pqforge's ciphertext to the same secret.
        final ss = native.decapsulate(alg, sk, enc.ciphertext);
        expect(
          ss,
          equals(enc.sharedSecret),
          reason: 'FIPS 203 byte-level interop (native sk + pqforge ct)',
        );
      },
    );

    test(
      '${alg.name}: cross-backend — pqforge key, native encapsulate, pqforge decapsulate',
      () {
        final kp = fallback.kemGenerate(alg);
        final (ct, ssEnc) = native.encapsulate(alg, kp.publicKey);
        final ssDec = fallback.kemDecapsulate(alg, kp.secretKey, ct);
        expect(
          ssDec,
          equals(ssEnc),
          reason: 'FIPS 203 byte-level interop (pqforge sk + native ct)',
        );
      },
    );
  }
}
