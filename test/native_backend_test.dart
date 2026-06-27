import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge_ffi/pqforge_ffi.dart';
import 'package:test/test.dart';

String _libPath() {
  final name = Platform.isWindows
      ? 'pqforge_core.dll'
      : Platform.isMacOS
          ? 'libpqforge_core.dylib'
          : 'libpqforge_core.so';
  return '${Directory.current.path}/rust/target/release/$name';
}

/// Phase 2.4 validation: the full native backend (ML-KEM + ML-DSA) satisfies the
/// `PqForgeBackend` contract and is byte-interoperable with the pure-Dart
/// `pqforge` fallback. Skipped cleanly when the native library is absent.
void main() {
  final libPath = _libPath();
  if (!File(libPath).existsSync()) {
    test('native backend tests',
        () {}, skip: 'native library not built at $libPath');
    return;
  }

  late final NativeBackend native;
  const fallback = FallbackBackend();
  final message =
      Uint8List.fromList([for (var i = 0; i < 200; i++) (i * 7) & 0xFF]);

  setUpAll(() => native = NativeBackend.open(libPath));

  test('reports native kind and matching ABI version', () {
    expect(native.kind, BackendKind.native);
    expect(native.abiVersion(), kPqForgeAbiVersion);
  });

  group('ML-KEM via the native backend', () {
    for (final alg in PqKemAlgorithm.values) {
      test('${alg.name} native round-trip', () {
        final kp = native.kemGenerate(alg);
        expect(kp.publicKey.length, alg.publicKeyBytes);
        expect(kp.secretKey.length, alg.secretKeyBytes);
        final enc = native.kemEncapsulate(alg, kp.publicKey);
        final ss = native.kemDecapsulate(alg, kp.secretKey, enc.ciphertext);
        expect(ss, equals(enc.sharedSecret));
      });

      test('${alg.name} cross-backend (native key, pqforge encapsulate)', () {
        final kp = native.kemGenerate(alg);
        final enc = fallback.kemEncapsulate(alg, kp.publicKey);
        expect(native.kemDecapsulate(alg, kp.secretKey, enc.ciphertext),
            equals(enc.sharedSecret));
      });
    }
  });

  group('ML-DSA via the native backend', () {
    for (final alg in PqSignatureAlgorithm.values) {
      test('${alg.name} native sign/verify + tamper rejection', () {
        final kp = native.signGenerate(alg);
        expect(kp.publicKey.length, alg.publicKeyBytes);
        final sig = native.sign(alg, kp.secretKey, message);
        expect(sig.length, alg.signatureBytes);
        expect(native.verify(alg, kp.publicKey, message, sig), isTrue);
        final tampered = Uint8List.fromList(message)..[0] ^= 0x01;
        expect(native.verify(alg, kp.publicKey, tampered, sig), isFalse);
      });

      test('${alg.name} cross-backend: native sign → pqforge verify', () {
        final kp = native.signGenerate(alg);
        final sig = native.sign(alg, kp.secretKey, message);
        expect(fallback.verify(alg, kp.publicKey, message, sig), isTrue,
            reason: 'FIPS 204 byte-level interop (native sig + key)');
      });

      test('${alg.name} cross-backend: pqforge sign → native verify', () {
        final kp = fallback.signGenerate(alg);
        final sig = fallback.sign(alg, kp.secretKey, message);
        expect(native.verify(alg, kp.publicKey, message, sig), isTrue,
            reason: 'FIPS 204 byte-level interop (pqforge sig + key)');
      });
    }
  });

  group('selector', () {
    test('PqForge.instance(nativeLibraryPath:) selects + uses the native backend',
        () {
      PqForge.reset();
      final pq = PqForge.instance(nativeLibraryPath: libPath);
      addTearDown(PqForge.reset);
      expect(pq.backendKind, BackendKind.native);
      expect(pq.isAccelerated, isTrue);

      // End-to-end through the selector facade.
      final kem = pq.generateKemKeyPair(PqKemAlgorithm.mlKem768);
      final enc = pq.encapsulate(PqKemAlgorithm.mlKem768, kem.publicKey);
      expect(
          pq.decapsulate(PqKemAlgorithm.mlKem768, kem.secretKey, enc.ciphertext),
          equals(enc.sharedSecret));
      final signer = pq.generateSignatureKeyPair(PqSignatureAlgorithm.mlDsa65);
      final sig = pq.sign(PqSignatureAlgorithm.mlDsa65, signer.secretKey, message);
      expect(pq.verify(PqSignatureAlgorithm.mlDsa65, signer.publicKey, message, sig),
          isTrue);
    });

    test('a bad library path degrades to the fallback (never throws)', () {
      PqForge.reset();
      addTearDown(PqForge.reset);
      final pq = PqForge.instance(nativeLibraryPath: '/no/such/pqforge_core.so');
      expect(pq.backendKind, BackendKind.fallback);
    });
  });
}
