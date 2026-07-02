import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge_ffi/pqforge_ffi.dart';
import 'package:test/test.dart';

/// Phase 3.1/3.2: the pure-Dart AEAD path (AES-256-GCM via pqforge,
/// ChaCha20-Poly1305 via PointyCastle). Runs with no native library present.
void main() {
  const fb = FallbackBackend();

  final key = Uint8List.fromList([
    for (var i = 0; i < 32; i++) (i * 7 + 1) & 0xFF,
  ]);
  final nonce = Uint8List.fromList([
    for (var i = 0; i < 12; i++) (i * 5 + 3) & 0xFF,
  ]);
  final aad = Uint8List.fromList(utf8.encode('header-v1'));
  final pt = Uint8List.fromList(utf8.encode('the quick brown fox jumps'));

  for (final alg in PqAeadAlgorithm.values) {
    group(alg.name, () {
      test('seal/open round-trip', () {
        final ct = fb.aeadSeal(alg, key, nonce, pt, aad);
        expect(ct.length, pt.length + alg.tagBytes);
        expect(fb.aeadOpen(alg, key, nonce, ct, aad), equals(pt));
      });

      test('tampered ciphertext throws VerificationFailedException', () {
        final ct = fb.aeadSeal(alg, key, nonce, pt, aad);
        final bad = Uint8List.fromList(ct)..[0] ^= 0xFF;
        expect(
          () => fb.aeadOpen(alg, key, nonce, bad, aad),
          throwsA(isA<VerificationFailedException>()),
        );
      });

      test('wrong AAD fails authentication', () {
        final ct = fb.aeadSeal(alg, key, nonce, pt, aad);
        final wrongAad = Uint8List.fromList(utf8.encode('header-v2'));
        expect(
          () => fb.aeadOpen(alg, key, nonce, ct, wrongAad),
          throwsA(isA<VerificationFailedException>()),
        );
      });

      test('wrong key length throws InvalidKeyException', () {
        expect(
          () => fb.aeadSeal(alg, Uint8List(16), nonce, pt, aad),
          throwsA(isA<InvalidKeyException>()),
        );
      });

      test('empty plaintext round-trips (tag only)', () {
        final ct = fb.aeadSeal(alg, key, nonce, Uint8List(0), Uint8List(0));
        expect(ct.length, alg.tagBytes);
        expect(fb.aeadOpen(alg, key, nonce, ct, Uint8List(0)), isEmpty);
      });
    });
  }
}
