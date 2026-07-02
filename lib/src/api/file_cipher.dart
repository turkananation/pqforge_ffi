import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../backend/backend.dart';
import '../model/errors.dart';
import 'stream.dart';

// (alg, key, keyLen, aad, aadLen, chunkSize, inPath, outPath) -> status
typedef _FileNative =
    Int32 Function(
      Int32,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Size,
      Pointer<Uint8>,
      Pointer<Uint8>,
    );
typedef _FileDart =
    int Function(
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      int,
      Pointer<Uint8>,
      Pointer<Uint8>,
    );

/// Native zero-FFI file encryption using the STREAM construction.
///
/// Reads and writes files **directly in Rust** (memory-bounded, no per-chunk FFI
/// crossing — the fast path for large / TB-scale files), in a wire format
/// identical to [PqForgeStream]: a file sealed here opens with the streaming
/// layer and vice-versa. The output is published **atomically** (written to a
/// temp file, then renamed on success; removed on any failure).
///
/// SECURITY: [seal] uses a counter-based per-frame nonce, so [key] MUST be unique
/// per file — reuse is catastrophic for AES-GCM / ChaCha-Poly1305.
class PqForgeFileCipher {
  PqForgeFileCipher._(this._sealFile, this._openFile);

  final _FileDart _sealFile;
  final _FileDart _openFile;

  /// Loads the native library at [libraryPath] and binds the file pipeline.
  /// Throws [NativeBindingException] if it cannot be loaded or a symbol is missing.
  factory PqForgeFileCipher.open(String libraryPath) {
    final DynamicLibrary lib;
    try {
      lib = DynamicLibrary.open(libraryPath);
    } on Object catch (e) {
      throw NativeBindingException('cannot open "$libraryPath": $e');
    }
    try {
      return PqForgeFileCipher._(
        lib.lookupFunction<_FileNative, _FileDart>('pqforge_stream_seal_file'),
        lib.lookupFunction<_FileNative, _FileDart>('pqforge_stream_open_file'),
      );
    } on Object catch (e) {
      throw NativeBindingException('file-pipeline symbol lookup failed: $e');
    }
  }

  /// Seals [inputPath] into [outputPath]. The caller MUST use a unique [key] per
  /// file. [chunkSize] must match the reader.
  Future<void> seal(
    String inputPath,
    String outputPath, {
    required Uint8List key,
    PqAeadAlgorithm algorithm = PqAeadAlgorithm.aes256Gcm,
    Uint8List? aad,
    int chunkSize = PqForgeStream.defaultChunkSize,
  }) => _run(
    _sealFile,
    inputPath,
    outputPath,
    key,
    algorithm,
    aad,
    chunkSize,
    'stream seal file',
  );

  /// Opens [inputPath] into [outputPath]. Throws a [VerificationFailedException]
  /// on tamper / reorder / truncation, or an [InvalidCiphertextException] on a
  /// malformed stream.
  Future<void> open(
    String inputPath,
    String outputPath, {
    required Uint8List key,
    PqAeadAlgorithm algorithm = PqAeadAlgorithm.aes256Gcm,
    Uint8List? aad,
    int chunkSize = PqForgeStream.defaultChunkSize,
  }) => _run(
    _openFile,
    inputPath,
    outputPath,
    key,
    algorithm,
    aad,
    chunkSize,
    'stream open file',
  );

  Future<void> _run(
    _FileDart fn,
    String inputPath,
    String outputPath,
    Uint8List key,
    PqAeadAlgorithm algorithm,
    Uint8List? aad,
    int chunkSize,
    String op,
  ) async {
    if (chunkSize <= 0) {
      throw ArgumentError.value(chunkSize, 'chunkSize', 'must be positive');
    }
    final ad = aad ?? Uint8List(0);
    final tmpPath = '$outputPath.pqforge-tmp';

    final k = _bytes(key);
    final a = _bytes(ad);
    final inPtr = _cString(inputPath);
    final outPtr = _cString(tmpPath);
    int rc;
    try {
      rc = fn(
        algorithm.id,
        k,
        key.length,
        a,
        ad.length,
        chunkSize,
        inPtr,
        outPtr,
      );
    } finally {
      calloc
        ..free(k)
        ..free(a)
        ..free(inPtr)
        ..free(outPtr);
    }

    if (rc != PqForgeErrorCode.ok.value) {
      await _deleteQuiet(tmpPath);
      _throwStatus(rc, op);
    }
    try {
      await File(tmpPath).rename(outputPath);
    } on Object {
      await _deleteQuiet(tmpPath);
      rethrow;
    }
  }
}

Pointer<Uint8> _bytes(Uint8List data) {
  final p = calloc<Uint8>(data.isEmpty ? 1 : data.length);
  if (data.isNotEmpty) p.asTypedList(data.length).setAll(0, data);
  return p;
}

/// Allocates a NUL-terminated UTF-8 copy of [s] (calloc zero-fills the terminator).
Pointer<Uint8> _cString(String s) {
  final bytes = utf8.encode(s);
  final p = calloc<Uint8>(bytes.length + 1);
  p.asTypedList(bytes.length).setAll(0, bytes);
  return p;
}

Future<void> _deleteQuiet(String path) async {
  try {
    final f = File(path);
    if (await f.exists()) await f.delete();
  } on Object {
    // best-effort cleanup
  }
}

Never _throwStatus(int rc, String op) {
  switch (PqForgeErrorCode.fromValue(rc)) {
    case PqForgeErrorCode.invalidKey:
      throw InvalidKeyException('$op: invalid key');
    case PqForgeErrorCode.invalidCiphertext:
      throw InvalidCiphertextException('$op: malformed ciphertext');
    case PqForgeErrorCode.authFailed:
      throw VerificationFailedException('$op: authentication failed');
    case PqForgeErrorCode.unsupported:
      throw UnsupportedBackendException('$op: unsupported');
    case PqForgeErrorCode.ok:
    case PqForgeErrorCode.unaligned:
    case PqForgeErrorCode.io:
    case PqForgeErrorCode.device:
    case PqForgeErrorCode.anchor:
    case PqForgeErrorCode.internal:
    case PqForgeErrorCode.nullArgument:
    case PqForgeErrorCode.bufferTooSmall:
      throw InternalCryptoException(
        '$op: ${PqForgeErrorCode.fromValue(rc).name} (status $rc)',
      );
  }
}
