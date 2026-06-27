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
typedef _KeygenNative = Int32 Function(
    Int32, Pointer<Uint8>, Size, Pointer<Size>, Pointer<Uint8>, Size, Pointer<Size>);
typedef _KeygenDart = int Function(
    int, Pointer<Uint8>, int, Pointer<Size>, Pointer<Uint8>, int, Pointer<Size>);

// encapsulate: (alg, pub, pubLen, ctOut, ctCap, ctLen, ssOut, ssCap, ssLen)
typedef _EncapNative = Int32 Function(Int32, Pointer<Uint8>, Size, Pointer<Uint8>,
    Size, Pointer<Size>, Pointer<Uint8>, Size, Pointer<Size>);
typedef _EncapDart = int Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int,
    Pointer<Size>, Pointer<Uint8>, int, Pointer<Size>);

// (alg, inA, inALen, inB, inBLen, out, outCap, outLen) — KEM decapsulate & DSA sign share this.
typedef _TwoInOneOutNative = Int32 Function(Int32, Pointer<Uint8>, Size,
    Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Size>);
typedef _TwoInOneOutDart = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Size>);

// verify: (alg, pub, pubLen, msg, msgLen, sig, sigLen)
typedef _VerifyNative = Int32 Function(
    Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _VerifyDart =
    int Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);

class _Bindings {
  _Bindings(DynamicLibrary lib)
      : abiVersion = lib
            .lookupFunction<_AbiVersionNative, _AbiVersionDart>('pqforge_abi_version'),
        cryptoSelftest = lib
            .lookupFunction<_SelftestNative, _SelftestDart>('pqforge_crypto_selftest'),
        mlkemKeygen = lib
            .lookupFunction<_KeygenNative, _KeygenDart>('pqforge_mlkem_keygen'),
        mlkemEncapsulate = lib
            .lookupFunction<_EncapNative, _EncapDart>('pqforge_mlkem_encapsulate'),
        mlkemDecapsulate = lib.lookupFunction<_TwoInOneOutNative, _TwoInOneOutDart>(
            'pqforge_mlkem_decapsulate'),
        mldsaKeygen = lib
            .lookupFunction<_KeygenNative, _KeygenDart>('pqforge_mldsa_keygen'),
        mldsaSign = lib.lookupFunction<_TwoInOneOutNative, _TwoInOneOutDart>(
            'pqforge_mldsa_sign'),
        mldsaVerify =
            lib.lookupFunction<_VerifyNative, _VerifyDart>('pqforge_mldsa_verify');

  final _AbiVersionDart abiVersion;
  final _SelftestDart cryptoSelftest;
  final _KeygenDart mlkemKeygen;
  final _EncapDart mlkemEncapsulate;
  final _TwoInOneOutDart mlkemDecapsulate;
  final _KeygenDart mldsaKeygen;
  final _TwoInOneOutDart mldsaSign;
  final _VerifyDart mldsaVerify;
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
      throw NativeBindingException('symbol lookup failed in "$libraryPath": $e');
    }
    final abi = b.abiVersion();
    if (abi != kPqForgeAbiVersion) {
      throw NativeBindingException(
          'ABI mismatch: native=$abi expected=$kPqForgeAbiVersion');
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
  PqKeyPair kemGenerate(PqKemAlgorithm algorithm) => _keygen(_b.mlkemKeygen,
      algorithm.index, algorithm.publicKeyBytes, algorithm.secretKeyBytes,
      'ML-KEM keygen');

  @override
  PqKemEncapsulation kemEncapsulate(
      PqKemAlgorithm algorithm, Uint8List publicKey) {
    final pub = _toNative(publicKey);
    final ct = calloc<Uint8>(algorithm.ciphertextBytes);
    final ss = calloc<Uint8>(algorithm.sharedSecretBytes);
    final cl = calloc<Size>();
    final sl = calloc<Size>();
    try {
      final rc = _b.mlkemEncapsulate(algorithm.index, pub, publicKey.length, ct,
          algorithm.ciphertextBytes, cl, ss, algorithm.sharedSecretBytes, sl);
      if (rc != PqForgeErrorCode.ok.value) _throwStatus(rc, 'ML-KEM encapsulate');
      return PqKemEncapsulation(
        algorithm: algorithm,
        ciphertext: Uint8List.fromList(ct.asTypedList(cl.value)),
        sharedSecret: Uint8List.fromList(ss.asTypedList(sl.value)),
      );
    } finally {
      calloc..free(pub)..free(ct)..free(ss)..free(cl)..free(sl);
    }
  }

  @override
  Uint8List kemDecapsulate(
          PqKemAlgorithm algorithm, Uint8List secretKey, Uint8List ciphertext) =>
      _twoInOneOut(_b.mlkemDecapsulate, algorithm.index, secretKey, ciphertext,
          algorithm.sharedSecretBytes, 'ML-KEM decapsulate');

  @override
  PqKeyPair signGenerate(PqSignatureAlgorithm algorithm) => _keygen(
      _b.mldsaKeygen, algorithm.index, algorithm.publicKeyBytes,
      algorithm.secretKeyBytes, 'ML-DSA keygen');

  @override
  Uint8List sign(PqSignatureAlgorithm algorithm, Uint8List secretKey,
          Uint8List message) =>
      _twoInOneOut(_b.mldsaSign, algorithm.index, secretKey, message,
          algorithm.signatureBytes, 'ML-DSA sign');

  @override
  bool verify(PqSignatureAlgorithm algorithm, Uint8List publicKey,
      Uint8List message, Uint8List signature) {
    final pub = _toNative(publicKey);
    final msg = _toNative(message);
    final sig = _toNative(signature);
    try {
      final rc = _b.mldsaVerify(algorithm.index, pub, publicKey.length, msg,
          message.length, sig, signature.length);
      // Ok = valid; AuthFailed / InvalidKey / etc. = not verified (never throws).
      return rc == PqForgeErrorCode.ok.value;
    } finally {
      calloc..free(pub)..free(msg)..free(sig);
    }
  }

  // --- shared marshalling helpers ---

  PqKeyPair _keygen(
      _KeygenDart fn, int algId, int pubBytes, int secBytes, String op) {
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
      calloc..free(pub)..free(sec)..free(pl)..free(sl);
    }
  }

  Uint8List _twoInOneOut(_TwoInOneOutDart fn, int algId, Uint8List inA,
      Uint8List inB, int outBytes, String op) {
    final a = _toNative(inA);
    final b = _toNative(inB);
    final out = calloc<Uint8>(outBytes);
    final ol = calloc<Size>();
    try {
      final rc = fn(algId, a, inA.length, b, inB.length, out, outBytes, ol);
      if (rc != PqForgeErrorCode.ok.value) _throwStatus(rc, op);
      return Uint8List.fromList(out.asTypedList(ol.value));
    } finally {
      calloc..free(a)..free(b)..free(out)..free(ol);
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
