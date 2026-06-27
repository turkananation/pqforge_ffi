/// Typed error taxonomy for pqforge_ffi.
///
/// Every backend — the native FFI core or the pure-Dart fallback — maps its
/// failures onto this one hierarchy, and the integer [PqForgeErrorCode] values
/// are the *same* status codes the Rust `extern "C"` boundary returns (Phase 1b).
/// So a failure means the same thing whichever backend produced it, and a panic
/// can never cross the FFI boundary as anything other than a typed code.
library;

/// Stable status codes shared with the Rust `extern "C"` boundary.
///
/// The integer values are part of the ABI: do not renumber. New codes append.
enum PqForgeErrorCode {
  ok(0),
  invalidKey(1),
  invalidCiphertext(2),
  authFailed(3),
  unaligned(4),
  io(5),
  device(6),
  anchor(7),
  unsupported(8),
  internal(9),
  nullArgument(10),
  bufferTooSmall(11);

  const PqForgeErrorCode(this.value);

  /// The on-the-wire integer returned by the native C-ABI.
  final int value;

  /// Maps a raw native status code back to its enum; unknown codes fold to
  /// [internal] (an unrecognized failure is still a failure).
  static PqForgeErrorCode fromValue(int value) {
    for (final code in values) {
      if (code.value == value) return code;
    }
    return PqForgeErrorCode.internal;
  }
}

/// Base type for every error pqforge_ffi raises. Sealed so callers can `switch`
/// exhaustively over the failure modes.
sealed class PqForgeFfiException implements Exception {
  const PqForgeFfiException(this.message, this.code);

  final String message;
  final PqForgeErrorCode code;

  @override
  String toString() => '$runtimeType(${code.name}): $message';
}

/// Key material was malformed (wrong length, wrong parameter set, corrupt).
final class InvalidKeyException extends PqForgeFfiException {
  const InvalidKeyException(String message)
      : super(message, PqForgeErrorCode.invalidKey);
}

/// A ciphertext / encapsulation was malformed or failed an integrity check.
final class InvalidCiphertextException extends PqForgeFfiException {
  const InvalidCiphertextException(String message)
      : super(message, PqForgeErrorCode.invalidCiphertext);
}

/// A signature or AEAD tag failed verification.
final class VerificationFailedException extends PqForgeFfiException {
  const VerificationFailedException(String message)
      : super(message, PqForgeErrorCode.authFailed);
}

/// The requested operation is not available on the active backend (e.g. raw
/// block-device I/O on the pure-Dart fallback).
final class UnsupportedBackendException extends PqForgeFfiException {
  const UnsupportedBackendException(String message)
      : super(message, PqForgeErrorCode.unsupported);
}

/// The native library could not be loaded, probed, or its ABI did not match.
final class NativeBindingException extends PqForgeFfiException {
  const NativeBindingException(String message)
      : super(message, PqForgeErrorCode.internal);
}

/// A cryptographic operation failed for an internal/unexpected reason
/// (including a recovered Rust panic crossing the FFI boundary).
final class InternalCryptoException extends PqForgeFfiException {
  const InternalCryptoException(String message)
      : super(message, PqForgeErrorCode.internal);
}
