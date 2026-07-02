import 'dart:typed_data';

import 'package:pqforge/pqforge.dart' as pq;

import '../backend/backend.dart';
import '../model/errors.dart';

/// Single-shot KEM-DEM envelope: encrypt a message to a recipient's ML-KEM
/// public key.
///
/// It composes the three proven, cross-backend-interoperable primitives —
/// **ML-KEM encapsulate → HKDF-SHA256 → AES-256-GCM seal** — so an envelope
/// sealed by the native backend opens on the pure-Dart fallback and vice versa.
/// The AEAD key is freshly derived per envelope (from a random salt and the
/// per-encapsulation shared secret), so nonce reuse is structurally impossible.
///
/// Wire format (v1, big-endian integers):
/// ```text
/// "PFE1"(4) | version(1) | kemAlgId(1) | aeadAlgId(1) |
/// salt(16) | nonce(12) | kemCtLen(u32) | kemCt | sealed(ciphertext||tag)
/// ```
/// The entire header (everything before `sealed`) plus any caller [aad] is bound
/// as the AEAD associated data, so tampering with any field — algorithm id,
/// salt, nonce, or KEM ciphertext — fails authentication.
class PqForgeEnvelope {
  const PqForgeEnvelope(this._backend);

  final PqForgeBackend _backend;

  static const List<int> _magic = [0x50, 0x46, 0x45, 0x31]; // "PFE1"
  static const int _version = 1;
  static const int _aeadAes256Gcm = 0;
  static const int _saltLen = 16;
  static const int _nonceLen = 12;
  // magic(4) + version(1) + kemAlgId(1) + aeadId(1) + salt + nonce + kemCtLen(4)
  static const int _headerFixedLen = 4 + 1 + 1 + 1 + _saltLen + _nonceLen + 4;

  static final Uint8List _info = Uint8List.fromList(
    'pqforge_ffi/v1/aes-256-gcm'.codeUnits,
  );

  /// Seals [plaintext] to [recipientPublicKey] under [kemAlgorithm]. Optional
  /// [aad] is authenticated (not encrypted) and must be supplied identically to
  /// [open].
  Uint8List seal(
    pq.PqKemAlgorithm kemAlgorithm,
    Uint8List recipientPublicKey,
    Uint8List plaintext, {
    Uint8List? aad,
  }) {
    final enc = _backend.kemEncapsulate(kemAlgorithm, recipientPublicKey);
    final salt = pq.PqBytes.randomBytes(_saltLen);
    final nonce = pq.PqBytes.randomBytes(_nonceLen);
    final key = pq.PqSymmetricPrimitives.hkdfSha256(
      ikm: enc.sharedSecret,
      salt: salt,
      info: _info,
      outputBytes: PqAeadAlgorithm.aes256Gcm.keyBytes,
    );
    final header = _encodeHeader(kemAlgorithm, salt, nonce, enc.ciphertext);
    final sealed = _backend.aeadSeal(
      PqAeadAlgorithm.aes256Gcm,
      key,
      nonce,
      plaintext,
      _authData(header, aad),
    );
    final out = Uint8List(header.length + sealed.length);
    out.setRange(0, header.length, header);
    out.setRange(header.length, out.length, sealed);
    return out;
  }

  /// Opens an [envelope] with [recipientSecretKey]. Throws an
  /// [InvalidCiphertextException] if the envelope is malformed, or a
  /// [VerificationFailedException] if authentication fails.
  Uint8List open(
    Uint8List recipientSecretKey,
    Uint8List envelope, {
    Uint8List? aad,
  }) {
    final parsed = _decode(envelope);
    final sharedSecret = _backend.kemDecapsulate(
      parsed.kemAlgorithm,
      recipientSecretKey,
      parsed.kemCiphertext,
    );
    final key = pq.PqSymmetricPrimitives.hkdfSha256(
      ikm: sharedSecret,
      salt: parsed.salt,
      info: _info,
      outputBytes: PqAeadAlgorithm.aes256Gcm.keyBytes,
    );
    return _backend.aeadOpen(
      PqAeadAlgorithm.aes256Gcm,
      key,
      parsed.nonce,
      parsed.sealed,
      _authData(parsed.header, aad),
    );
  }

  Uint8List _authData(Uint8List header, Uint8List? aad) {
    if (aad == null || aad.isEmpty) return header;
    final out = Uint8List(header.length + aad.length);
    out.setRange(0, header.length, header);
    out.setRange(header.length, out.length, aad);
    return out;
  }

  Uint8List _encodeHeader(
    pq.PqKemAlgorithm kemAlg,
    Uint8List salt,
    Uint8List nonce,
    Uint8List kemCt,
  ) {
    final header = Uint8List(_headerFixedLen + kemCt.length);
    var o = 0;
    header.setAll(o, _magic);
    o += 4;
    header[o++] = _version;
    header[o++] = kemAlg.index;
    header[o++] = _aeadAes256Gcm;
    header.setAll(o, salt);
    o += _saltLen;
    header.setAll(o, nonce);
    o += _nonceLen;
    _writeU32(header, o, kemCt.length);
    o += 4;
    header.setAll(o, kemCt);
    return header;
  }

  _ParsedEnvelope _decode(Uint8List e) {
    if (e.length < _headerFixedLen) {
      throw const InvalidCiphertextException('envelope too short for header');
    }
    for (var i = 0; i < 4; i++) {
      if (e[i] != _magic[i]) {
        throw const InvalidCiphertextException('bad envelope magic');
      }
    }
    var o = 4;
    final version = e[o++];
    if (version != _version) {
      throw InvalidCiphertextException('unsupported envelope version $version');
    }
    final kemAlgId = e[o++];
    if (kemAlgId >= pq.PqKemAlgorithm.values.length) {
      throw InvalidCiphertextException('bad KEM algorithm id $kemAlgId');
    }
    final kemAlg = pq.PqKemAlgorithm.values[kemAlgId];
    final aeadId = e[o++];
    if (aeadId != _aeadAes256Gcm) {
      throw InvalidCiphertextException('unsupported AEAD id $aeadId');
    }
    final salt = Uint8List.sublistView(e, o, o + _saltLen);
    o += _saltLen;
    final nonce = Uint8List.sublistView(e, o, o + _nonceLen);
    o += _nonceLen;
    final kemCtLen = _readU32(e, o);
    o += 4;
    if (kemCtLen != kemAlg.ciphertextBytes) {
      throw InvalidCiphertextException(
        'KEM ciphertext length $kemCtLen != ${kemAlg.ciphertextBytes}',
      );
    }
    if (o + kemCtLen > e.length) {
      throw const InvalidCiphertextException('truncated KEM ciphertext');
    }
    final kemCt = Uint8List.sublistView(e, o, o + kemCtLen);
    o += kemCtLen;
    final header = Uint8List.sublistView(e, 0, o);
    final sealed = Uint8List.sublistView(e, o);
    return _ParsedEnvelope(kemAlg, salt, nonce, kemCt, header, sealed);
  }

  static void _writeU32(Uint8List b, int o, int v) {
    b[o] = (v >> 24) & 0xFF;
    b[o + 1] = (v >> 16) & 0xFF;
    b[o + 2] = (v >> 8) & 0xFF;
    b[o + 3] = v & 0xFF;
  }

  static int _readU32(Uint8List b, int o) =>
      (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3];
}

class _ParsedEnvelope {
  _ParsedEnvelope(
    this.kemAlgorithm,
    this.salt,
    this.nonce,
    this.kemCiphertext,
    this.header,
    this.sealed,
  );

  final pq.PqKemAlgorithm kemAlgorithm;
  final Uint8List salt;
  final Uint8List nonce;
  final Uint8List kemCiphertext;
  final Uint8List header;
  final Uint8List sealed;
}
