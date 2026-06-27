import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:pqforge/pqforge.dart' as pq;
import 'package:pqforge_ffi/pqforge_ffi.dart';
import 'package:test/test.dart';

typedef _SeedKeygenNative = Int32 Function(Int32, Pointer<Uint8>, Size,
    Pointer<Uint8>, Size, Pointer<Size>, Pointer<Uint8>, Size, Pointer<Size>);
typedef _SeedKeygenDart = int Function(int, Pointer<Uint8>, int, Pointer<Uint8>,
    int, Pointer<Size>, Pointer<Uint8>, int, Pointer<Size>);

String _libPath() {
  final name = Platform.isWindows
      ? 'pqforge_core.dll'
      : Platform.isMacOS
          ? 'libpqforge_core.dylib'
          : 'libpqforge_core.so';
  return '${Directory.current.path}/rust/target/release/$name';
}

(Uint8List, Uint8List) _nativeFromSeed(
    _SeedKeygenDart fn, PqSignatureAlgorithm alg, Uint8List seed) {
  final s = calloc<Uint8>(seed.length)..asTypedList(seed.length).setAll(0, seed);
  final pub = calloc<Uint8>(alg.publicKeyBytes);
  final sec = calloc<Uint8>(alg.secretKeyBytes);
  final pl = calloc<Size>();
  final sl = calloc<Size>();
  try {
    final rc = fn(alg.index, s, seed.length, pub, alg.publicKeyBytes, pl, sec,
        alg.secretKeyBytes, sl);
    expect(rc, PqForgeErrorCode.ok.value);
    return (
      Uint8List.fromList(pub.asTypedList(pl.value)),
      Uint8List.fromList(sec.asTypedList(sl.value)),
    );
  } finally {
    calloc..free(s)..free(pub)..free(sec)..free(pl)..free(sl);
  }
}

/// Phase 2.4 known-answer tests. The strongest correctness check short of
/// official NIST ACVP vectors: a *cross-implementation* KAT — the native AWS-LC
/// `from_seed` must derive the same FIPS-204 key as pqforge's seeded keygen from
/// the same 32-byte seed (two independent `KeyGen(ξ)` implementations agreeing).
void main() {
  final libPath = _libPath();
  if (!File(libPath).existsSync()) {
    test('ML-DSA KATs',
        () {}, skip: 'native library not built at $libPath');
    return;
  }

  late final _SeedKeygenDart nativeSeedKeygen;
  setUpAll(() {
    final lib = DynamicLibrary.open(libPath);
    nativeSeedKeygen = lib.lookupFunction<_SeedKeygenNative, _SeedKeygenDart>(
        'pqforge_mldsa_keygen_from_seed');
  });

  for (final alg in PqSignatureAlgorithm.values) {
    test('${alg.name}: native from_seed is deterministic', () {
      final seed =
          Uint8List.fromList([for (var i = 0; i < 32; i++) (i * 3 + 1) & 0xFF]);
      final (pub1, sec1) = _nativeFromSeed(nativeSeedKeygen, alg, seed);
      final (pub2, sec2) = _nativeFromSeed(nativeSeedKeygen, alg, seed);
      expect(pub1, equals(pub2));
      expect(sec1, equals(sec2));
      expect(pub1.length, alg.publicKeyBytes);
      expect(sec1.length, alg.secretKeyBytes);
    });

    test(
        '${alg.name}: cross-implementation KAT — native from_seed == pqforge seeded keygen',
        () {
      final seed =
          Uint8List.fromList([for (var i = 0; i < 32; i++) (i * 5 + 2) & 0xFF]);
      final (nativePub, nativeSec) = _nativeFromSeed(nativeSeedKeygen, alg, seed);
      final pqKp = pq.PqSignaturePrimitives.generateKeyPairSeeded(alg, seed);
      expect(nativePub, equals(pqKp.publicKey),
          reason: 'two independent FIPS-204 KeyGen(ξ) must agree on the public key');
      expect(nativeSec, equals(pqKp.secretKey),
          reason: 'expanded secret keys must agree');
    });
  }
}
