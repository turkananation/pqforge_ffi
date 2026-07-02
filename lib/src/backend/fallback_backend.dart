import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;
import 'package:pqforge/pqforge.dart' as pq;

import '../model/errors.dart';
import 'backend.dart';

/// Pure-Dart backend over the `pqforge` toolkit (pqcrypto + PointyCastle).
///
/// This is the always-available path: it needs no native library, so the
/// package works on every Dart/Flutter target and degrades cleanly when the
/// accelerated native binary is absent or fails to load. Its output is
/// wire-compatible with the native backend by construction — both implement
/// FIPS 203 / FIPS 204 over the same parameter sets.
final class FallbackBackend implements PqForgeBackend {
  const FallbackBackend();

  @override
  BackendKind get kind => BackendKind.fallback;

  @override
  int abiVersion() => kPqForgeAbiVersion;

  @override
  pq.PqKeyPair kemGenerate(pq.PqKemAlgorithm algorithm) =>
      _guard(() => pq.PqKemPrimitives.generateKeyPair(algorithm));

  @override
  pq.PqKemEncapsulation kemEncapsulate(
    pq.PqKemAlgorithm algorithm,
    Uint8List publicKey,
  ) => _guard(() => pq.PqKemPrimitives.encapsulate(algorithm, publicKey));

  @override
  Uint8List kemDecapsulate(
    pq.PqKemAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List ciphertext,
  ) => _guard(
    () => pq.PqKemPrimitives.decapsulate(algorithm, secretKey, ciphertext),
  );

  @override
  pq.PqKeyPair signGenerate(pq.PqSignatureAlgorithm algorithm) =>
      _guard(() => pq.PqSignaturePrimitives.generateKeyPair(algorithm));

  @override
  Uint8List sign(
    pq.PqSignatureAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List message,
  ) => _guard(
    () => pq.PqSignaturePrimitives.sign(algorithm, secretKey, message),
  );

  @override
  bool verify(
    pq.PqSignatureAlgorithm algorithm,
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) => _guard(
    () => pq.PqSignaturePrimitives.verify(
      algorithm,
      publicKey,
      message,
      signature,
    ),
  );

  @override
  Uint8List aeadSeal(
    PqAeadAlgorithm algorithm,
    Uint8List key,
    Uint8List nonce,
    Uint8List plaintext,
    Uint8List aad,
  ) {
    switch (algorithm) {
      case PqAeadAlgorithm.aes256Gcm:
        try {
          return pq.PqSymmetricPrimitives.aesGcmEncrypt(
            key: key,
            nonce: nonce,
            plaintext: plaintext,
            aad: aad,
          );
        } on ArgumentError catch (e) {
          throw InvalidKeyException(e.toString());
        }
      case PqAeadAlgorithm.chaCha20Poly1305:
        _requireSizes(algorithm, key, nonce);
        return _runAead(
          _chacha(forEncryption: true, key: key, nonce: nonce, aad: aad),
          plaintext,
        );
    }
  }

  @override
  Uint8List aeadOpen(
    PqAeadAlgorithm algorithm,
    Uint8List key,
    Uint8List nonce,
    Uint8List ciphertext,
    Uint8List aad,
  ) {
    switch (algorithm) {
      case PqAeadAlgorithm.aes256Gcm:
        try {
          return pq.PqSymmetricPrimitives.aesGcmDecrypt(
            key: key,
            nonce: nonce,
            ciphertext: ciphertext,
            aad: aad,
          );
        } on ArgumentError catch (e) {
          throw InvalidKeyException(e.toString());
        } on Object {
          // Any GCM failure on well-formed inputs is a tag/authentication failure.
          throw const VerificationFailedException(
            'AEAD tag verification failed',
          );
        }
      case PqAeadAlgorithm.chaCha20Poly1305:
        _requireSizes(algorithm, key, nonce);
        if (ciphertext.length < algorithm.tagBytes) {
          throw const InvalidCiphertextException(
            'ciphertext shorter than the AEAD tag',
          );
        }
        try {
          return _runAead(
            _chacha(forEncryption: false, key: key, nonce: nonce, aad: aad),
            ciphertext,
          );
        } on Object {
          // Sizes are pre-validated, so any failure here is a failed tag check.
          // (PointyCastle reports this as an ArgumentError, not a typed AEAD error.)
          throw const VerificationFailedException(
            'AEAD tag verification failed',
          );
        }
    }
  }

  static void _requireSizes(
    PqAeadAlgorithm algorithm,
    Uint8List key,
    Uint8List nonce,
  ) {
    if (key.length != algorithm.keyBytes) {
      throw InvalidKeyException(
        '${algorithm.name} key must be ${algorithm.keyBytes} bytes',
      );
    }
    if (nonce.length != algorithm.nonceBytes) {
      throw InvalidKeyException(
        '${algorithm.name} nonce must be ${algorithm.nonceBytes} bytes',
      );
    }
  }

  // RFC 8439 ChaCha20-Poly1305 (the same construction pqforge uses), so output
  // is byte-compatible with the native AWS-LC backend.
  static pc.ChaCha20Poly1305 _chacha({
    required bool forEncryption,
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List aad,
  }) => pc.ChaCha20Poly1305(pc.ChaCha7539Engine(), pc.Poly1305())
    ..init(
      forEncryption,
      pc.AEADParameters(pc.KeyParameter(key), 128, nonce, aad),
    );

  /// Drives a PointyCastle AEAD cipher to completion, zeroizing the output if it
  /// throws — a failed tag check on decryption leaves unauthenticated plaintext
  /// in the buffer, which must never linger.
  static Uint8List _runAead(pc.ChaCha20Poly1305 cipher, Uint8List data) {
    final out = Uint8List(cipher.getOutputSize(data.length));
    try {
      final n = cipher.processBytes(data, 0, data.length, out, 0);
      final written = n + cipher.doFinal(out, n);
      return written == out.length
          ? out
          : Uint8List.sublistView(out, 0, written);
    } catch (_) {
      out.fillRange(0, out.length, 0);
      rethrow;
    }
  }

  /// Maps `pqforge` / argument failures onto the pqforge_ffi taxonomy so callers
  /// see one error hierarchy regardless of which backend answered.
  T _guard<T>(T Function() body) {
    try {
      return body();
    } on PqForgeFfiException {
      rethrow;
    } on pq.PqForgeException catch (e) {
      throw InvalidCiphertextException(e.message);
    } on ArgumentError catch (e) {
      throw InvalidKeyException(e.toString());
    } on Object catch (e) {
      throw InternalCryptoException(e.toString());
    }
  }
}
