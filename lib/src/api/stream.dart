import 'dart:typed_data';

import '../backend/backend.dart';
import '../model/errors.dart';

/// Streaming authenticated encryption for arbitrarily large (TB-scale) data,
/// using the **STREAM** construction (Hoang-Reyhanitabar-Rogaway-Vizár; the same
/// scheme `age` uses).
///
/// The payload is split into fixed-size frames. Each frame is sealed under the
/// per-stream [key] with a nonce of `big-endian counter ‖ last-flag`, so:
/// * frames cannot be **reordered** (the counter is part of the authenticated
///   nonce),
/// * the stream cannot be **truncated or extended** (only the genuine final
///   frame carries `last = 1`; dropping or appending a frame flips a flag and
///   fails authentication).
///
/// It is a memory-bounded composition over the backend AEAD primitive, so a
/// stream sealed by the native backend opens on the pure-Dart fallback and
/// vice-versa.
///
/// SECURITY: [key] MUST be unique per stream. The per-frame nonce is a counter,
/// so reusing a key across two streams reuses (key, nonce) pairs — catastrophic
/// for AES-GCM/ChaCha-Poly1305. Derive a fresh random key (or a KEM/HKDF key)
/// for every stream.
class PqForgeStream {
  const PqForgeStream(this._backend);

  final PqForgeBackend _backend;

  /// Default plaintext frame size (64 KiB), matching `age`.
  static const int defaultChunkSize = 64 * 1024;

  /// Seals a plaintext [source] into a stream of `ciphertext‖tag` frames.
  Stream<Uint8List> seal(
    Stream<List<int>> source, {
    required Uint8List key,
    PqAeadAlgorithm algorithm = PqAeadAlgorithm.aes256Gcm,
    Uint8List? aad,
    int chunkSize = defaultChunkSize,
  }) async* {
    if (chunkSize <= 0) {
      throw ArgumentError.value(chunkSize, 'chunkSize', 'must be positive');
    }
    final ad = aad ?? Uint8List(0);
    var counter = 0;
    // The most recent full chunk, held back until we know whether it is the
    // last (we only learn that when the source ends).
    Uint8List? pending;
    var carry = Uint8List(0); // leftover < chunkSize

    await for (final data in source) {
      final combined = _concat(carry, data);
      var offset = 0;
      while (combined.length - offset >= chunkSize) {
        if (pending != null) {
          yield _seal(key, algorithm, pending, counter++, false, ad);
        }
        pending = Uint8List.fromList(
          Uint8List.sublistView(combined, offset, offset + chunkSize),
        );
        offset += chunkSize;
      }
      carry = Uint8List.fromList(Uint8List.sublistView(combined, offset));
    }

    if (carry.isNotEmpty) {
      if (pending != null) {
        yield _seal(key, algorithm, pending, counter++, false, ad);
      }
      yield _seal(key, algorithm, carry, counter++, true, ad);
    } else if (pending != null) {
      yield _seal(key, algorithm, pending, counter++, true, ad);
    } else {
      // Empty input → a single empty final frame (tag only).
      yield _seal(key, algorithm, Uint8List(0), counter++, true, ad);
    }
  }

  /// Opens a [source] of frames produced by [seal] back into plaintext chunks.
  /// Throws a [VerificationFailedException] on any tamper / reorder / truncation
  /// / extension, or an [InvalidCiphertextException] on a malformed frame.
  Stream<Uint8List> open(
    Stream<List<int>> source, {
    required Uint8List key,
    PqAeadAlgorithm algorithm = PqAeadAlgorithm.aes256Gcm,
    Uint8List? aad,
    int chunkSize = defaultChunkSize,
  }) async* {
    if (chunkSize <= 0) {
      throw ArgumentError.value(chunkSize, 'chunkSize', 'must be positive');
    }
    final ad = aad ?? Uint8List(0);
    final cipherChunk = chunkSize + algorithm.tagBytes;
    var counter = 0;
    var carry = Uint8List(0);
    var sawAnyByte = false;

    await for (final data in source) {
      if (data.isNotEmpty) sawAnyByte = true;
      final combined = _concat(carry, data);
      var offset = 0;
      // A frame is non-last only if STRICTLY more than one cipher-frame remains
      // (something must follow it). The trailing `cipherChunk` is held back as
      // the potential final frame.
      while (combined.length - offset > cipherChunk) {
        final frame = Uint8List.sublistView(
          combined,
          offset,
          offset + cipherChunk,
        );
        yield _open(key, algorithm, frame, counter++, false, ad);
        offset += cipherChunk;
      }
      carry = Uint8List.fromList(Uint8List.sublistView(combined, offset));
    }

    if (!sawAnyByte) {
      throw const InvalidCiphertextException('empty ciphertext stream');
    }
    if (carry.length < algorithm.tagBytes) {
      throw const InvalidCiphertextException('truncated final frame');
    }
    yield _open(key, algorithm, carry, counter++, true, ad);
  }

  Uint8List _seal(
    Uint8List key,
    PqAeadAlgorithm alg,
    Uint8List chunk,
    int counter,
    bool last,
    Uint8List aad,
  ) => _backend.aeadSeal(
    alg,
    key,
    _nonce(counter, last, alg.nonceBytes),
    chunk,
    aad,
  );

  Uint8List _open(
    Uint8List key,
    PqAeadAlgorithm alg,
    Uint8List frame,
    int counter,
    bool last,
    Uint8List aad,
  ) => _backend.aeadOpen(
    alg,
    key,
    _nonce(counter, last, alg.nonceBytes),
    frame,
    aad,
  );

  /// Nonce = big-endian [counter] in the leading bytes, [last] flag in the final
  /// byte. With a 12-byte nonce this is an 88-bit counter space.
  static Uint8List _nonce(int counter, bool last, int nonceBytes) {
    final nonce = Uint8List(nonceBytes);
    var c = counter;
    for (var i = nonceBytes - 2; i >= 0 && c > 0; i--) {
      nonce[i] = c & 0xFF;
      c >>= 8;
    }
    nonce[nonceBytes - 1] = last ? 1 : 0;
    return nonce;
  }

  static Uint8List _concat(Uint8List a, List<int> b) {
    if (a.isEmpty) return b is Uint8List ? b : Uint8List.fromList(b);
    final out = Uint8List(a.length + b.length);
    out.setRange(0, a.length, a);
    out.setRange(a.length, out.length, b);
    return out;
  }
}
