import 'dart:typed_data';

import 'package:pqforge_ffi/pqforge_ffi.dart';
import 'package:test/test.dart';

/// Phase 1a validation: the pure-Dart fallback must satisfy the full backend
/// contract with NO native library present. These tests are the executable
/// specification the native backend will later be held to.
void main() {
  const backend = FallbackBackend();

  // A fixed, non-trivial message (every byte value 0..255).
  final message = Uint8List.fromList([for (var i = 0; i < 256; i++) i & 0xFF]);

  test('reports fallback kind and the matching ABI version', () {
    expect(backend.kind, BackendKind.fallback);
    expect(backend.abiVersion(), kPqForgeAbiVersion);
  });

  group('ML-KEM (FIPS 203)', () {
    for (final alg in PqKemAlgorithm.values) {
      test('${alg.name} key sizes and encapsulate/decapsulate agree', () {
        final kp = backend.kemGenerate(alg);
        expect(kp.publicKey.length, alg.publicKeyBytes);
        expect(kp.secretKey.length, alg.secretKeyBytes);

        final enc = backend.kemEncapsulate(alg, kp.publicKey);
        expect(enc.ciphertext.length, alg.ciphertextBytes);
        expect(enc.sharedSecret.length, alg.sharedSecretBytes);

        final recovered = backend.kemDecapsulate(
          alg,
          kp.secretKey,
          enc.ciphertext,
        );
        expect(
          recovered,
          equals(enc.sharedSecret),
          reason: 'decapsulated secret must equal the encapsulated one',
        );
      });
    }

    test('a wrong-length public key throws InvalidKeyException', () {
      expect(
        () => backend.kemEncapsulate(PqKemAlgorithm.mlKem768, Uint8List(10)),
        throwsA(isA<InvalidKeyException>()),
      );
    });

    test(
      'a corrupted ciphertext yields a different secret (implicit rejection)',
      () {
        const alg = PqKemAlgorithm.mlKem768;
        final kp = backend.kemGenerate(alg);
        final enc = backend.kemEncapsulate(alg, kp.publicKey);
        final tampered = Uint8List.fromList(enc.ciphertext)..[0] ^= 0xFF;

        final recovered = backend.kemDecapsulate(alg, kp.secretKey, tampered);
        // ML-KEM never errors on a bad ciphertext; it returns a pseudo-random
        // secret derived from the key, which differs from the real one.
        expect(recovered, isNot(equals(enc.sharedSecret)));
      },
    );
  });

  group('ML-DSA (FIPS 204)', () {
    for (final alg in PqSignatureAlgorithm.values) {
      test('${alg.name} sign/verify agree and sizes match', () {
        final kp = backend.signGenerate(alg);
        expect(kp.publicKey.length, alg.publicKeyBytes);
        expect(kp.secretKey.length, alg.secretKeyBytes);

        final sig = backend.sign(alg, kp.secretKey, message);
        expect(sig.length, alg.signatureBytes);
        expect(backend.verify(alg, kp.publicKey, message, sig), isTrue);
      });

      test('${alg.name} rejects a tampered message', () {
        final kp = backend.signGenerate(alg);
        final sig = backend.sign(alg, kp.secretKey, message);
        final badMessage = Uint8List.fromList(message)..[0] ^= 0x01;
        expect(backend.verify(alg, kp.publicKey, badMessage, sig), isFalse);
      });

      test('${alg.name} rejects a tampered signature', () {
        final kp = backend.signGenerate(alg);
        final sig = backend.sign(alg, kp.secretKey, message);
        final badSig = Uint8List.fromList(sig)..[0] ^= 0x01;
        expect(backend.verify(alg, kp.publicKey, message, badSig), isFalse);
      });

      test('${alg.name} rejects a signature made under a different key', () {
        final a = backend.signGenerate(alg);
        final b = backend.signGenerate(alg);
        final sig = backend.sign(alg, a.secretKey, message);
        expect(backend.verify(alg, b.publicKey, message, sig), isFalse);
      });
    }
  });

  group('selector', () {
    test(
      'resolves the pure-Dart fallback when no native library is present',
      () {
        PqForge.reset();
        final pq = PqForge.instance();
        expect(pq.backendKind, BackendKind.fallback);
        expect(pq.isAccelerated, isFalse);
      },
    );

    test('end-to-end via the selector: ML-KEM + ML-DSA round-trip', () {
      PqForge.reset();
      final pq = PqForge.instance();

      final kem = pq.generateKemKeyPair(PqKemAlgorithm.mlKem512);
      final enc = pq.encapsulate(PqKemAlgorithm.mlKem512, kem.publicKey);
      final ss = pq.decapsulate(
        PqKemAlgorithm.mlKem512,
        kem.secretKey,
        enc.ciphertext,
      );
      expect(ss, equals(enc.sharedSecret));

      final signer = pq.generateSignatureKeyPair(PqSignatureAlgorithm.mlDsa44);
      final sig = pq.sign(
        PqSignatureAlgorithm.mlDsa44,
        signer.secretKey,
        message,
      );
      expect(
        pq.verify(PqSignatureAlgorithm.mlDsa44, signer.publicKey, message, sig),
        isTrue,
      );
    });
  });
}
