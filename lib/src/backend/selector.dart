import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

import 'backend.dart';
import 'fallback_backend.dart';
import 'native_backend.dart';

/// The package entry point. Resolves the best available backend exactly once
/// and exposes the accelerated operations through it.
final class PqForge {
  PqForge._(this.backend);

  /// The resolved backend (native when available and validated, else the
  /// pure-Dart fallback).
  final PqForgeBackend backend;

  static PqForge? _instance;

  /// Resolves (once) and returns the process singleton.
  ///
  /// When [preferNative] is true and [nativeLibraryPath] points at a loadable
  /// `pqforge_core` library, the accelerated [NativeBackend] is used (after ABI
  /// + AWS-LC self-test validation); any failure degrades **silently** to the
  /// pure-Dart [FallbackBackend]. With no path (the default), the fallback is
  /// used until Native Assets bundling lands (Phase 6).
  factory PqForge.instance({
    bool preferNative = true,
    String? nativeLibraryPath,
  }) =>
      _instance ??= PqForge._(_resolveBackend(preferNative, nativeLibraryPath));

  /// Test/diagnostic seam: install an explicit backend and reset the singleton.
  static PqForge withBackend(PqForgeBackend backend) =>
      _instance = PqForge._(backend);

  /// Clears the cached singleton so the next [PqForge.instance] re-resolves.
  static void reset() => _instance = null;

  static PqForgeBackend _resolveBackend(
    bool preferNative,
    String? nativeLibraryPath,
  ) {
    if (preferNative && nativeLibraryPath != null) {
      try {
        return NativeBackend.open(nativeLibraryPath);
      } on Object {
        // Missing library, bad symbol, ABI mismatch, or self-test failure all
        // fall through to the always-available pure-Dart backend.
      }
    }
    return const FallbackBackend();
  }

  /// Whether the resolved backend is the hardware-accelerated native one.
  bool get isAccelerated => backend.kind == BackendKind.native;

  /// Which backend answered (native vs fallback).
  BackendKind get backendKind => backend.kind;

  // --- Convenience pass-throughs over the active backend ---

  PqKeyPair generateKemKeyPair(PqKemAlgorithm algorithm) =>
      backend.kemGenerate(algorithm);

  PqKemEncapsulation encapsulate(PqKemAlgorithm algorithm, Uint8List publicKey) =>
      backend.kemEncapsulate(algorithm, publicKey);

  Uint8List decapsulate(
    PqKemAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List ciphertext,
  ) =>
      backend.kemDecapsulate(algorithm, secretKey, ciphertext);

  PqKeyPair generateSignatureKeyPair(PqSignatureAlgorithm algorithm) =>
      backend.signGenerate(algorithm);

  Uint8List sign(
    PqSignatureAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List message,
  ) =>
      backend.sign(algorithm, secretKey, message);

  bool verify(
    PqSignatureAlgorithm algorithm,
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) =>
      backend.verify(algorithm, publicKey, message, signature);
}
