import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge_ffi/pqforge_ffi.dart';

/// Minimal end-to-end demo of pqforge_ffi.
///
/// In Phase 1 this runs on the pure-Dart fallback (no native library yet), so
/// it works anywhere `dart run` works. When the native backend is bundled the
/// exact same code transparently uses the accelerated path.
void main() {
  final pq = PqForge.instance();
  print('backend: ${pq.backendKind.name} (accelerated: ${pq.isAccelerated})');

  // ML-KEM-768 encapsulate / decapsulate.
  const kem = PqKemAlgorithm.mlKem768;
  final kemKeys = pq.generateKemKeyPair(kem);
  final enc = pq.encapsulate(kem, kemKeys.publicKey);
  final shared = pq.decapsulate(kem, kemKeys.secretKey, enc.ciphertext);
  print('ML-KEM-768 shared secret match: '
      '${base64Encode(shared) == base64Encode(enc.sharedSecret)}');

  // ML-DSA-65 sign / verify.
  const sig = PqSignatureAlgorithm.mlDsa65;
  final signKeys = pq.generateSignatureKeyPair(sig);
  final message = Uint8List.fromList(utf8.encode('attack at dawn'));
  final signature = pq.sign(sig, signKeys.secretKey, message);
  print('ML-DSA-65 verify: '
      '${pq.verify(sig, signKeys.publicKey, message, signature)}');
}
