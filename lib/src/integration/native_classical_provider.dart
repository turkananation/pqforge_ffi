import 'dart:typed_data';

import 'package:pqforge/pqforge.dart' as pq;

import '../backend/native_backend.dart';

/// Native (AWS-LC) backend for pqforge's classical seam
/// ([pq.PqClassical.provider]).
///
/// Accelerates the classical half of the hybrid stack — X25519 key agreement and
/// Ed25519 signatures — through aws-lc-rs. Registering an instance makes the
/// whole pqforge hybrid handshake (`initiate`/`accept`, hybrid signing) run on
/// native X25519/Ed25519, byte-identical to the pure-Dart default (RFC 7748 and
/// RFC 8032 are deterministic; proven by pqforge's conformance harness):
///
/// ```dart
/// pq.PqClassical.provider = NativePqforgeClassicalProvider.open(libraryPath);
/// // ...the classical half of every pqforge hybrid API is now native...
/// pq.PqClassical.useDefault(); // restore the pure-Dart provider
/// ```
///
/// **ECDSA-P256 falls through to [fallback]** (default
/// [pq.PqPureDartClassicalProvider]): aws-lc-rs exposes no raw-scalar-only ECDSA
/// key constructor, so the pure-Dart PointyCastle path (RFC-6979) stays
/// authoritative for P-256. X25519 and Ed25519 are the hybrid defaults, so the
/// common path is fully accelerated.
class NativePqforgeClassicalProvider implements pq.PqClassicalProvider {
  /// Wraps an already-open [NativeBackend]. [fallback] handles ECDSA-P256
  /// (defaults to the pure-Dart provider).
  NativePqforgeClassicalProvider(
    this._native, {
    this.fallback = const pq.PqPureDartClassicalProvider(),
  });

  /// Opens the native library at [libraryPath] and wraps it.
  factory NativePqforgeClassicalProvider.open(
    String libraryPath, {
    pq.PqClassicalProvider fallback = const pq.PqPureDartClassicalProvider(),
  }) => NativePqforgeClassicalProvider(
    NativeBackend.open(libraryPath),
    fallback: fallback,
  );

  final NativeBackend _native;

  /// The provider handling ECDSA-P256 (which aws-lc-rs can't do from a bare
  /// scalar).
  final pq.PqClassicalProvider fallback;

  /// The native backend this provider accelerates with.
  NativeBackend get backend => _native;

  @override
  String get name => 'pqforge-ffi-awslc-classical';

  // --- X25519 (native) ---

  @override
  Future<({Uint8List publicKey, Uint8List secretKey})> x25519GenerateKeyPair({
    Uint8List? seed,
  }) => Future.value(_native.x25519Generate(seed: seed));

  @override
  Future<Uint8List> x25519SharedSecret({
    required Uint8List secretKey,
    required Uint8List remotePublicKey,
  }) => Future.value(_native.x25519SharedSecret(secretKey, remotePublicKey));

  // --- Ed25519 (native) ---

  @override
  Future<({Uint8List publicKey, Uint8List secretKey})> ed25519GenerateKeyPair({
    Uint8List? seed,
  }) => Future.value(_native.ed25519Generate(seed: seed));

  @override
  Future<Uint8List> ed25519PublicKeyFromSeed(Uint8List seed) =>
      Future.value(_native.ed25519PublicFromSeed(seed));

  @override
  Future<Uint8List> ed25519Sign({
    required Uint8List secretKey,
    required Uint8List publicKey,
    required Uint8List message,
  }) =>
      // The Ed25519 public key is derived from the seed, so `publicKey` is
      // redundant here (kept for interface parity with the pure-Dart provider).
      Future.value(_native.ed25519Sign(secretKey, message));

  @override
  Future<bool> ed25519Verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) => Future.value(_native.ed25519Verify(publicKey, message, signature));

  // --- ECDSA-P256 (delegated to the pure-Dart fallback) ---

  @override
  Future<({Uint8List publicKey, Uint8List secretKey})>
  ecdsaP256GenerateKeyPair() => fallback.ecdsaP256GenerateKeyPair();

  @override
  Future<Uint8List> ecdsaP256PublicKeyFromPrivate(Uint8List secretKey) =>
      fallback.ecdsaP256PublicKeyFromPrivate(secretKey);

  @override
  Future<Uint8List> ecdsaP256Sign({
    required Uint8List secretKey,
    required Uint8List message,
  }) => fallback.ecdsaP256Sign(secretKey: secretKey, message: message);

  @override
  Future<bool> ecdsaP256Verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) => fallback.ecdsaP256Verify(
    publicKey: publicKey,
    message: message,
    signature: signature,
  );
}
