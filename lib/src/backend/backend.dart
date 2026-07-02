import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

/// ABI version of the native C boundary. The selector refuses to use a native
/// library whose `pqforge_abi_version()` does not equal this. Bump when the
/// `extern "C"` surface changes shape.
const int kPqForgeAbiVersion = 1;

/// Identifies which implementation answered a call (diagnostics + tests).
enum BackendKind { native, fallback }

/// AEAD suites supported across both backends. [id] is the native C-ABI
/// algorithm id; sizes are in bytes.
enum PqAeadAlgorithm {
  aes256Gcm(id: 0, keyBytes: 32, nonceBytes: 12, tagBytes: 16),
  chaCha20Poly1305(id: 1, keyBytes: 32, nonceBytes: 12, tagBytes: 16);

  const PqAeadAlgorithm({
    required this.id,
    required this.keyBytes,
    required this.nonceBytes,
    required this.tagBytes,
  });

  final int id;
  final int keyBytes;
  final int nonceBytes;
  final int tagBytes;
}

/// The single contract both the native (FFI) backend and the pure-Dart
/// [FallbackBackend] satisfy.
///
/// This interface is the **specification** the Rust C-ABI must satisfy: it is
/// defined and tested against the pure-Dart fallback first, so when the native
/// implementation is wired behind it the behaviour is already pinned by tests.
///
/// Every method is total: it returns a value or throws a [PqForgeFfiException]
/// subtype (see `model/errors.dart`). No method returns a partially formed key
/// or secret. Types are `pqforge`'s own ([PqKeyPair], [PqKemEncapsulation],
/// [PqKemAlgorithm], [PqSignatureAlgorithm]) so the native and fallback paths
/// are wire-compatible by construction.
abstract interface class PqForgeBackend {
  /// native vs fallback.
  BackendKind get kind;

  /// The ABI version this backend implements (must equal [kPqForgeAbiVersion]).
  int abiVersion();

  // --- ML-KEM (FIPS 203) ---

  /// Generates an ML-KEM key pair for [algorithm].
  PqKeyPair kemGenerate(PqKemAlgorithm algorithm);

  /// Encapsulates to [publicKey], returning the ciphertext + shared secret.
  PqKemEncapsulation kemEncapsulate(
    PqKemAlgorithm algorithm,
    Uint8List publicKey,
  );

  /// Decapsulates [ciphertext] with [secretKey], returning the shared secret.
  /// ML-KEM uses implicit rejection: a corrupt ciphertext yields a *different*
  /// secret rather than an error.
  Uint8List kemDecapsulate(
    PqKemAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List ciphertext,
  );

  // --- ML-DSA (FIPS 204) ---

  /// Generates an ML-DSA signing key pair for [algorithm].
  PqKeyPair signGenerate(PqSignatureAlgorithm algorithm);

  /// Signs [message] with [secretKey].
  Uint8List sign(
    PqSignatureAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List message,
  );

  /// Verifies [signature] over [message] under [publicKey]. Returns `false`
  /// (never throws) for a bad signature, tampered message, or wrong key.
  bool verify(
    PqSignatureAlgorithm algorithm,
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  );

  // --- AEAD (FIPS 197 / SP 800-38D) ---

  /// Seals [plaintext] under [key]/[nonce] with associated data [aad],
  /// returning `ciphertext || tag`. The caller MUST ensure [nonce] is unique
  /// per [key] — AES-GCM nonce reuse is catastrophic.
  Uint8List aeadSeal(
    PqAeadAlgorithm algorithm,
    Uint8List key,
    Uint8List nonce,
    Uint8List plaintext,
    Uint8List aad,
  );

  /// Verifies and decrypts [ciphertext] (`ct || tag`). Throws a
  /// `VerificationFailedException` if the tag is invalid.
  Uint8List aeadOpen(
    PqAeadAlgorithm algorithm,
    Uint8List key,
    Uint8List nonce,
    Uint8List ciphertext,
    Uint8List aad,
  );
}
