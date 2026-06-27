import 'dart:typed_data';

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
  ) =>
      _guard(() => pq.PqKemPrimitives.encapsulate(algorithm, publicKey));

  @override
  Uint8List kemDecapsulate(
    pq.PqKemAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List ciphertext,
  ) =>
      _guard(
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
  ) =>
      _guard(() => pq.PqSignaturePrimitives.sign(algorithm, secretKey, message));

  @override
  bool verify(
    pq.PqSignatureAlgorithm algorithm,
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) =>
      _guard(
        () => pq.PqSignaturePrimitives.verify(
          algorithm,
          publicKey,
          message,
          signature,
        ),
      );

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
