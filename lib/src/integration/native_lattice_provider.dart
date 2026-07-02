import 'dart:typed_data';

import 'package:pqforge/pqforge.dart' as pq;

import '../backend/native_backend.dart';

/// Bridges the native AWS-LC engine into pqforge's swappable lattice seam.
///
/// Registering an instance as [pq.PqLattice.provider] makes the *entire* pqforge
/// toolkit — KEM-DEM envelopes, multi-recipient, hybrid key agreement/signing,
/// and the CLI — run on the hardware-accelerated ML-KEM / ML-DSA backend, with no
/// change to any pqforge caller:
///
/// ```dart
/// pq.PqLattice.provider = NativePqforgeLatticeProvider.open(libraryPath);
/// // ...every pqforge API is now native-accelerated...
/// pq.PqLattice.useDefault(); // restore the pure-Dart provider
/// ```
///
/// aws-lc-rs cannot honour three operations the pure-Dart provider supports, so
/// they transparently fall through to [fallback] (default
/// [pq.PqPureDartLatticeProvider]) — keeping the full contract and conformance:
///
///  * **seeded ML-KEM keygen** — aws-lc-rs ML-KEM keygen is randomized only;
///  * **nonce'd ML-KEM encapsulation** — aws-lc-rs encapsulation is randomized;
///  * **ML-DSA signing with a context or pre-hash** — the native `sign` accepts
///    neither.
///
/// Native ML-DSA keygen-from-seed *is* byte-identical to pqforge (KAT-proven), so
/// `dsaGenerateKeyPairSeeded` stays on the accelerated path.
class NativePqforgeLatticeProvider implements pq.PqLatticeProvider {
  /// Wraps an already-open [NativeBackend]. [fallback] handles the operations
  /// aws-lc-rs cannot perform (defaults to the pure-Dart provider).
  NativePqforgeLatticeProvider(
    this._native, {
    this.fallback = const pq.PqPureDartLatticeProvider(),
  });

  /// Opens the native library at [libraryPath] and wraps it.
  factory NativePqforgeLatticeProvider.open(
    String libraryPath, {
    pq.PqLatticeProvider fallback = const pq.PqPureDartLatticeProvider(),
  }) => NativePqforgeLatticeProvider(
    NativeBackend.open(libraryPath),
    fallback: fallback,
  );

  final NativeBackend _native;

  /// The provider handling operations aws-lc-rs cannot perform.
  final pq.PqLatticeProvider fallback;

  /// The native backend this provider accelerates with.
  NativeBackend get backend => _native;

  @override
  String get name => 'pqforge-ffi-awslc-lattice';

  @override
  (Uint8List, Uint8List) kemGenerateKeyPair(
    pq.PqKemAlgorithm algorithm, {
    Uint8List? seed,
  }) {
    // aws-lc-rs ML-KEM keygen is randomized — honour a caller-supplied seed via
    // the deterministic pure-Dart path.
    if (seed != null) {
      return fallback.kemGenerateKeyPair(algorithm, seed: seed);
    }
    final kp = _native.kemGenerate(algorithm);
    return (kp.publicKey, kp.secretKey);
  }

  @override
  (Uint8List, Uint8List) kemEncapsulate(
    pq.PqKemAlgorithm algorithm,
    Uint8List publicKey, {
    Uint8List? nonce,
  }) {
    // aws-lc-rs encapsulation draws its own randomness — a caller-supplied nonce
    // can only be honoured by the deterministic pure-Dart path.
    if (nonce != null) {
      return fallback.kemEncapsulate(algorithm, publicKey, nonce: nonce);
    }
    final e = _native.kemEncapsulate(algorithm, publicKey);
    return (e.ciphertext, e.sharedSecret);
  }

  @override
  Uint8List kemDecapsulate(
    pq.PqKemAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List ciphertext,
  ) => _native.kemDecapsulate(algorithm, secretKey, ciphertext);

  @override
  (Uint8List, Uint8List) dsaGenerateKeyPair(pq.PqSignatureAlgorithm algorithm) {
    final kp = _native.signGenerate(algorithm);
    return (kp.publicKey, kp.secretKey);
  }

  @override
  (Uint8List, Uint8List) dsaGenerateKeyPairSeeded(
    pq.PqSignatureAlgorithm algorithm,
    Uint8List seed,
  ) {
    final kp = _native.signGenerateFromSeed(algorithm, seed);
    return (kp.publicKey, kp.secretKey);
  }

  @override
  Uint8List dsaSign(
    pq.PqSignatureAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List message, {
    Uint8List? context,
    bool preHash = false,
  }) {
    // The native `sign` takes neither a context nor a pre-hash flag; route those
    // FIPS-204 variants through the pure-Dart provider.
    if (preHash || (context != null && context.isNotEmpty)) {
      return fallback.dsaSign(
        algorithm,
        secretKey,
        message,
        context: context,
        preHash: preHash,
      );
    }
    return _native.sign(algorithm, secretKey, message);
  }

  @override
  bool dsaVerify(
    pq.PqSignatureAlgorithm algorithm,
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature, {
    Uint8List? context,
    bool preHash = false,
  }) {
    if (preHash || (context != null && context.isNotEmpty)) {
      return fallback.dsaVerify(
        algorithm,
        publicKey,
        message,
        signature,
        context: context,
        preHash: preHash,
      );
    }
    return _native.verify(algorithm, publicKey, message, signature);
  }
}
