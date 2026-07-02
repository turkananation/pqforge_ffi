import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:pqforge/pqforge.dart';

import '../model/errors.dart';
import 'backend.dart';

// --- C-ABI signatures (mirror rust/crates/pqforge_core/src/**) ---
typedef _AbiVersionNative = Uint32 Function();
typedef _AbiVersionDart = int Function();
typedef _SelftestNative = Int32 Function();
typedef _SelftestDart = int Function();

// keygen: (alg, pubOut, pubCap, pubLen, secOut, secCap, secLen) — KEM & DSA share this.
typedef _KeygenNative =
    Int32 Function(
      Int32,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
    );
typedef _KeygenDart =
    int Function(
      int,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
    );

// encapsulate: (alg, pub, pubLen, ctOut, ctCap, ctLen, ssOut, ssCap, ssLen)
typedef _EncapNative =
    Int32 Function(
      Int32,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
    );
typedef _EncapDart =
    int Function(
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
    );

// (alg, inA, inALen, inB, inBLen, out, outCap, outLen) — KEM decapsulate & DSA sign share this.
typedef _TwoInOneOutNative =
    Int32 Function(
      Int32,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
    );
typedef _TwoInOneOutDart =
    int Function(
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
    );

// verify: (alg, pub, pubLen, msg, msgLen, sig, sigLen)
typedef _VerifyNative =
    Int32 Function(
      Int32,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
    );
typedef _VerifyDart =
    int Function(
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
    );

// aead seal/open: (alg, key, keyLen, nonce, nonceLen, aad, aadLen, in, inLen, out, outCap, outLen)
typedef _AeadNative =
    Int32 Function(
      Int32,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
    );
typedef _AeadDart =
    int Function(
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
    );

// (alg, seed, seedLen, pubOut, pubCap, pubLen, secOut, secCap, secLen) -> status
typedef _SeedKeygenNative =
    Int32 Function(
      Int32,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
    );
typedef _SeedKeygenDart =
    int Function(
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
    );

// classical keygen: (seed, seedLen, pubOut, pubCap, pubLen, secOut, secCap, secLen).
// `seed` may be null (nullptr) for CSPRNG keygen. X25519 & Ed25519 share this.
typedef _ClassicalKeygenNative =
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
    );
typedef _ClassicalKeygenDart =
    int Function(
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
    );

// (inA, inALen, inB, inBLen, out, outCap, outLen) — X25519 ECDH & Ed25519 sign.
typedef _ClassicalTwoInOneOutNative =
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
    );
typedef _ClassicalTwoInOneOutDart =
    int Function(
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
    );

// ed25519 public-from-seed: (seed, seedLen, pubOut, pubCap, pubLen)
typedef _PubFromSeedNative =
    Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Size>);
typedef _PubFromSeedDart =
    int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Size>);

// ed25519 verify: (pub, pubLen, msg, msgLen, sig, sigLen)
typedef _ClassicalVerifyNative =
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
    );
typedef _ClassicalVerifyDart =
    int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);

class _Bindings {
  _Bindings(DynamicLibrary lib)
    : abiVersion = lib.lookupFunction<_AbiVersionNative, _AbiVersionDart>(
        'pqforge_abi_version',
      ),
      cryptoSelftest = lib.lookupFunction<_SelftestNative, _SelftestDart>(
        'pqforge_crypto_selftest',
      ),
      mlkemKeygen = lib.lookupFunction<_KeygenNative, _KeygenDart>(
        'pqforge_mlkem_keygen',
      ),
      mlkemEncapsulate = lib.lookupFunction<_EncapNative, _EncapDart>(
        'pqforge_mlkem_encapsulate',
      ),
      mlkemDecapsulate = lib
          .lookupFunction<_TwoInOneOutNative, _TwoInOneOutDart>(
            'pqforge_mlkem_decapsulate',
          ),
      mldsaKeygen = lib.lookupFunction<_KeygenNative, _KeygenDart>(
        'pqforge_mldsa_keygen',
      ),
      mldsaSign = lib.lookupFunction<_TwoInOneOutNative, _TwoInOneOutDart>(
        'pqforge_mldsa_sign',
      ),
      mldsaVerify = lib.lookupFunction<_VerifyNative, _VerifyDart>(
        'pqforge_mldsa_verify',
      ),
      aeadSeal = lib.lookupFunction<_AeadNative, _AeadDart>(
        'pqforge_aead_seal',
      ),
      aeadOpen = lib.lookupFunction<_AeadNative, _AeadDart>(
        'pqforge_aead_open',
      ),
      mldsaKeygenFromSeed = lib
          .lookupFunction<_SeedKeygenNative, _SeedKeygenDart>(
            'pqforge_mldsa_keygen_from_seed',
          ),
      x25519Keygen = lib
          .lookupFunction<_ClassicalKeygenNative, _ClassicalKeygenDart>(
            'pqforge_x25519_keygen',
          ),
      x25519Ecdh = lib
          .lookupFunction<
            _ClassicalTwoInOneOutNative,
            _ClassicalTwoInOneOutDart
          >('pqforge_x25519_ecdh'),
      ed25519Keygen = lib
          .lookupFunction<_ClassicalKeygenNative, _ClassicalKeygenDart>(
            'pqforge_ed25519_keygen',
          ),
      ed25519PublicFromSeed = lib
          .lookupFunction<_PubFromSeedNative, _PubFromSeedDart>(
            'pqforge_ed25519_public_from_seed',
          ),
      ed25519Sign = lib
          .lookupFunction<
            _ClassicalTwoInOneOutNative,
            _ClassicalTwoInOneOutDart
          >('pqforge_ed25519_sign'),
      ed25519Verify = lib
          .lookupFunction<_ClassicalVerifyNative, _ClassicalVerifyDart>(
            'pqforge_ed25519_verify',
          );

  final _AbiVersionDart abiVersion;
  final _SelftestDart cryptoSelftest;
  final _KeygenDart mlkemKeygen;
  final _EncapDart mlkemEncapsulate;
  final _TwoInOneOutDart mlkemDecapsulate;
  final _KeygenDart mldsaKeygen;
  final _TwoInOneOutDart mldsaSign;
  final _VerifyDart mldsaVerify;
  final _AeadDart aeadSeal;
  final _AeadDart aeadOpen;
  final _SeedKeygenDart mldsaKeygenFromSeed;
  final _ClassicalKeygenDart x25519Keygen;
  final _ClassicalTwoInOneOutDart x25519Ecdh;
  final _ClassicalKeygenDart ed25519Keygen;
  final _PubFromSeedDart ed25519PublicFromSeed;
  final _ClassicalTwoInOneOutDart ed25519Sign;
  final _ClassicalVerifyDart ed25519Verify;
}

/// Hardware-accelerated backend over the native `pqforge_core` library
/// (AWS-LC). ML-KEM and ML-DSA use raw FIPS 203/204 bytes, so its output is
/// interchangeable with the pure-Dart [FallbackBackend].
final class NativeBackend implements PqForgeBackend {
  NativeBackend._(this._b);

  final _Bindings _b;

  /// Opens and validates the native library at [libraryPath]. Throws
  /// [NativeBindingException] if it cannot be loaded, a symbol is missing, the
  /// ABI version does not match, or the AWS-LC self-test fails.
  factory NativeBackend.open(String libraryPath) {
    final DynamicLibrary lib;
    try {
      lib = DynamicLibrary.open(libraryPath);
    } on Object catch (e) {
      throw NativeBindingException('cannot open "$libraryPath": $e');
    }
    final _Bindings b;
    try {
      b = _Bindings(lib);
    } on Object catch (e) {
      throw NativeBindingException(
        'symbol lookup failed in "$libraryPath": $e',
      );
    }
    final abi = b.abiVersion();
    if (abi != kPqForgeAbiVersion) {
      throw NativeBindingException(
        'ABI mismatch: native=$abi expected=$kPqForgeAbiVersion',
      );
    }
    if (b.cryptoSelftest() != PqForgeErrorCode.ok.value) {
      throw const NativeBindingException('AWS-LC crypto self-test failed');
    }
    return NativeBackend._(b);
  }

  @override
  BackendKind get kind => BackendKind.native;

  @override
  int abiVersion() => _b.abiVersion();

  @override
  PqKeyPair kemGenerate(PqKemAlgorithm algorithm) => _keygen(
    _b.mlkemKeygen,
    algorithm.index,
    algorithm.publicKeyBytes,
    algorithm.secretKeyBytes,
    'ML-KEM keygen',
  );

  @override
  PqKemEncapsulation kemEncapsulate(
    PqKemAlgorithm algorithm,
    Uint8List publicKey,
  ) {
    final pub = _toNative(publicKey);
    final ct = calloc<Uint8>(algorithm.ciphertextBytes);
    final ss = calloc<Uint8>(algorithm.sharedSecretBytes);
    final cl = calloc<Size>();
    final sl = calloc<Size>();
    try {
      final rc = _b.mlkemEncapsulate(
        algorithm.index,
        pub,
        publicKey.length,
        ct,
        algorithm.ciphertextBytes,
        cl,
        ss,
        algorithm.sharedSecretBytes,
        sl,
      );
      if (rc != PqForgeErrorCode.ok.value) {
        _throwStatus(rc, 'ML-KEM encapsulate');
      }
      return PqKemEncapsulation(
        algorithm: algorithm,
        ciphertext: Uint8List.fromList(ct.asTypedList(cl.value)),
        sharedSecret: Uint8List.fromList(ss.asTypedList(sl.value)),
      );
    } finally {
      calloc
        ..free(pub)
        ..free(ct)
        ..free(ss)
        ..free(cl)
        ..free(sl);
    }
  }

  @override
  Uint8List kemDecapsulate(
    PqKemAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List ciphertext,
  ) => _twoInOneOut(
    _b.mlkemDecapsulate,
    algorithm.index,
    secretKey,
    ciphertext,
    algorithm.sharedSecretBytes,
    'ML-KEM decapsulate',
  );

  @override
  PqKeyPair signGenerate(PqSignatureAlgorithm algorithm) => _keygen(
    _b.mldsaKeygen,
    algorithm.index,
    algorithm.publicKeyBytes,
    algorithm.secretKeyBytes,
    'ML-DSA keygen',
  );

  /// Deterministic ML-DSA key generation from a 32-byte seed (native-only; not
  /// part of [PqForgeBackend]). Byte-identical to pqforge's seeded keygen, so it
  /// backs `dsaGenerateKeyPairSeeded` in the pqforge lattice provider.
  PqKeyPair signGenerateFromSeed(
    PqSignatureAlgorithm algorithm,
    Uint8List seed,
  ) {
    final s = _toNative(seed);
    final pub = calloc<Uint8>(algorithm.publicKeyBytes);
    final sec = calloc<Uint8>(algorithm.secretKeyBytes);
    final pl = calloc<Size>();
    final sl = calloc<Size>();
    try {
      final rc = _b.mldsaKeygenFromSeed(
        algorithm.index,
        s,
        seed.length,
        pub,
        algorithm.publicKeyBytes,
        pl,
        sec,
        algorithm.secretKeyBytes,
        sl,
      );
      if (rc != PqForgeErrorCode.ok.value) {
        _throwStatus(rc, 'ML-DSA keygen from seed');
      }
      return PqKeyPair(
        publicKey: Uint8List.fromList(pub.asTypedList(pl.value)),
        secretKey: Uint8List.fromList(sec.asTypedList(sl.value)),
      );
    } finally {
      calloc
        ..free(s)
        ..free(pub)
        ..free(sec)
        ..free(pl)
        ..free(sl);
    }
  }

  @override
  Uint8List sign(
    PqSignatureAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List message,
  ) => _twoInOneOut(
    _b.mldsaSign,
    algorithm.index,
    secretKey,
    message,
    algorithm.signatureBytes,
    'ML-DSA sign',
  );

  @override
  bool verify(
    PqSignatureAlgorithm algorithm,
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) {
    final pub = _toNative(publicKey);
    final msg = _toNative(message);
    final sig = _toNative(signature);
    try {
      final rc = _b.mldsaVerify(
        algorithm.index,
        pub,
        publicKey.length,
        msg,
        message.length,
        sig,
        signature.length,
      );
      // Ok = valid; AuthFailed / InvalidKey / etc. = not verified (never throws).
      return rc == PqForgeErrorCode.ok.value;
    } finally {
      calloc
        ..free(pub)
        ..free(msg)
        ..free(sig);
    }
  }

  @override
  Uint8List aeadSeal(
    PqAeadAlgorithm algorithm,
    Uint8List key,
    Uint8List nonce,
    Uint8List plaintext,
    Uint8List aad,
  ) => _aead(
    _b.aeadSeal,
    algorithm.id,
    key,
    nonce,
    aad,
    plaintext,
    plaintext.length + algorithm.tagBytes,
    'AEAD seal',
  );

  @override
  Uint8List aeadOpen(
    PqAeadAlgorithm algorithm,
    Uint8List key,
    Uint8List nonce,
    Uint8List ciphertext,
    Uint8List aad,
  ) {
    final outBytes = ciphertext.length >= algorithm.tagBytes
        ? ciphertext.length - algorithm.tagBytes
        : 0;
    return _aead(
      _b.aeadOpen,
      algorithm.id,
      key,
      nonce,
      aad,
      ciphertext,
      outBytes,
      'AEAD open',
    );
  }

  // --- classical (X25519 / Ed25519) — native-only; back the pqforge
  //     `PqClassicalProvider` seam. Not part of `PqForgeBackend`. A key is its
  //     raw 32-byte seed/scalar, matching `package:cryptography`. ---

  /// X25519 key pair. With [seed] null a fresh key is drawn from the CSPRNG;
  /// otherwise the 32-byte [seed] is the private key (deterministic keygen).
  ({Uint8List publicKey, Uint8List secretKey}) x25519Generate({
    Uint8List? seed,
  }) => _classicalKeygen(_b.x25519Keygen, seed, 32, 32, 'X25519 keygen');

  /// X25519 ECDH: 32-byte shared secret from our 32-byte [secretKey] and a
  /// 32-byte [remotePublicKey].
  Uint8List x25519SharedSecret(
    Uint8List secretKey,
    Uint8List remotePublicKey,
  ) => _classicalTwoInOneOut(
    _b.x25519Ecdh,
    secretKey,
    remotePublicKey,
    32,
    'X25519 ECDH',
  );

  /// Ed25519 key pair (the secret key is the 32-byte seed). With [seed] null a
  /// fresh seed is drawn from the CSPRNG; otherwise [seed] is used.
  ({Uint8List publicKey, Uint8List secretKey}) ed25519Generate({
    Uint8List? seed,
  }) => _classicalKeygen(_b.ed25519Keygen, seed, 32, 32, 'Ed25519 keygen');

  /// The 32-byte Ed25519 public key derived from a 32-byte [seed].
  Uint8List ed25519PublicFromSeed(Uint8List seed) {
    final s = _toNative(seed);
    final pub = calloc<Uint8>(32);
    final pl = calloc<Size>();
    try {
      final rc = _b.ed25519PublicFromSeed(s, seed.length, pub, 32, pl);
      if (rc != PqForgeErrorCode.ok.value) {
        _throwStatus(rc, 'Ed25519 public from seed');
      }
      return Uint8List.fromList(pub.asTypedList(pl.value));
    } finally {
      calloc
        ..free(s)
        ..free(pub)
        ..free(pl);
    }
  }

  /// The 64-byte Ed25519 signature over [message] under a 32-byte [seed]
  /// (RFC 8032 deterministic — byte-identical to the pure-Dart provider).
  Uint8List ed25519Sign(Uint8List seed, Uint8List message) =>
      _classicalTwoInOneOut(_b.ed25519Sign, seed, message, 64, 'Ed25519 sign');

  /// Verifies a 64-byte Ed25519 [signature] over [message] under a 32-byte
  /// [publicKey]. Never throws — a malformed or invalid input returns false.
  bool ed25519Verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) {
    final pub = _toNative(publicKey);
    final msg = _toNative(message);
    final sig = _toNative(signature);
    try {
      final rc = _b.ed25519Verify(
        pub,
        publicKey.length,
        msg,
        message.length,
        sig,
        signature.length,
      );
      return rc == PqForgeErrorCode.ok.value;
    } finally {
      calloc
        ..free(pub)
        ..free(msg)
        ..free(sig);
    }
  }

  ({Uint8List publicKey, Uint8List secretKey}) _classicalKeygen(
    _ClassicalKeygenDart fn,
    Uint8List? seed,
    int pubBytes,
    int secBytes,
    String op,
  ) {
    // A null seed → nullptr, telling the native side to draw fresh randomness.
    final Pointer<Uint8> s = seed == null ? nullptr : _toNative(seed);
    final pub = calloc<Uint8>(pubBytes);
    final sec = calloc<Uint8>(secBytes);
    final pl = calloc<Size>();
    final sl = calloc<Size>();
    try {
      final rc = fn(s, seed?.length ?? 0, pub, pubBytes, pl, sec, secBytes, sl);
      if (rc != PqForgeErrorCode.ok.value) _throwStatus(rc, op);
      return (
        publicKey: Uint8List.fromList(pub.asTypedList(pl.value)),
        secretKey: Uint8List.fromList(sec.asTypedList(sl.value)),
      );
    } finally {
      if (seed != null) calloc.free(s);
      calloc
        ..free(pub)
        ..free(sec)
        ..free(pl)
        ..free(sl);
    }
  }

  Uint8List _classicalTwoInOneOut(
    _ClassicalTwoInOneOutDart fn,
    Uint8List inA,
    Uint8List inB,
    int outBytes,
    String op,
  ) {
    final a = _toNative(inA);
    final b = _toNative(inB);
    final out = calloc<Uint8>(outBytes);
    final ol = calloc<Size>();
    try {
      final rc = fn(a, inA.length, b, inB.length, out, outBytes, ol);
      if (rc != PqForgeErrorCode.ok.value) _throwStatus(rc, op);
      return Uint8List.fromList(out.asTypedList(ol.value));
    } finally {
      calloc
        ..free(a)
        ..free(b)
        ..free(out)
        ..free(ol);
    }
  }

  // --- shared marshalling helpers ---

  PqKeyPair _keygen(
    _KeygenDart fn,
    int algId,
    int pubBytes,
    int secBytes,
    String op,
  ) {
    final pub = calloc<Uint8>(pubBytes);
    final sec = calloc<Uint8>(secBytes);
    final pl = calloc<Size>();
    final sl = calloc<Size>();
    try {
      final rc = fn(algId, pub, pubBytes, pl, sec, secBytes, sl);
      if (rc != PqForgeErrorCode.ok.value) _throwStatus(rc, op);
      return PqKeyPair(
        publicKey: Uint8List.fromList(pub.asTypedList(pl.value)),
        secretKey: Uint8List.fromList(sec.asTypedList(sl.value)),
      );
    } finally {
      calloc
        ..free(pub)
        ..free(sec)
        ..free(pl)
        ..free(sl);
    }
  }

  Uint8List _twoInOneOut(
    _TwoInOneOutDart fn,
    int algId,
    Uint8List inA,
    Uint8List inB,
    int outBytes,
    String op,
  ) {
    final a = _toNative(inA);
    final b = _toNative(inB);
    final out = calloc<Uint8>(outBytes);
    final ol = calloc<Size>();
    try {
      final rc = fn(algId, a, inA.length, b, inB.length, out, outBytes, ol);
      if (rc != PqForgeErrorCode.ok.value) _throwStatus(rc, op);
      return Uint8List.fromList(out.asTypedList(ol.value));
    } finally {
      calloc
        ..free(a)
        ..free(b)
        ..free(out)
        ..free(ol);
    }
  }

  Uint8List _aead(
    _AeadDart fn,
    int algId,
    Uint8List key,
    Uint8List nonce,
    Uint8List aad,
    Uint8List input,
    int outBytes,
    String op,
  ) {
    final k = _toNative(key);
    final n = _toNative(nonce);
    final a = _toNative(aad);
    final inp = _toNative(input);
    final out = calloc<Uint8>(outBytes == 0 ? 1 : outBytes);
    final ol = calloc<Size>();
    try {
      final rc = fn(
        algId,
        k,
        key.length,
        n,
        nonce.length,
        a,
        aad.length,
        inp,
        input.length,
        out,
        outBytes,
        ol,
      );
      if (rc != PqForgeErrorCode.ok.value) _throwStatus(rc, op);
      return Uint8List.fromList(out.asTypedList(ol.value));
    } finally {
      calloc
        ..free(k)
        ..free(n)
        ..free(a)
        ..free(inp)
        ..free(out)
        ..free(ol);
    }
  }
}

Pointer<Uint8> _toNative(Uint8List data) {
  final p = calloc<Uint8>(data.isEmpty ? 1 : data.length);
  if (data.isNotEmpty) p.asTypedList(data.length).setAll(0, data);
  return p;
}

Never _throwStatus(int rc, String op) {
  final code = PqForgeErrorCode.fromValue(rc);
  switch (code) {
    case PqForgeErrorCode.invalidKey:
      throw InvalidKeyException('$op: invalid key');
    case PqForgeErrorCode.invalidCiphertext:
      throw InvalidCiphertextException('$op: invalid ciphertext');
    case PqForgeErrorCode.authFailed:
      throw VerificationFailedException('$op: verification failed');
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
      throw InternalCryptoException('$op: ${code.name} (status $rc)');
  }
}
