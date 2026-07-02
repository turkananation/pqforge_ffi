import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge_ffi/pqforge_ffi.dart';
import 'package:test/test.dart';

String _libPath() {
  final name = Platform.isWindows
      ? 'pqforge_core.dll'
      : Platform.isMacOS
      ? 'libpqforge_core.dylib'
      : 'libpqforge_core.so';
  return '${Directory.current.path}/rust/target/release/$name';
}

/// Phase 3.1/3.2 validation: native AWS-LC AEAD is byte-interoperable with the
/// pure-Dart fallback (AES-256-GCM via pqforge, ChaCha20-Poly1305 via
/// PointyCastle), for the same `ct || tag` wire format. Skipped without the lib.
void main() {
  final libPath = _libPath();
  if (!File(libPath).existsSync()) {
    test(
      'native AEAD tests',
      () {},
      skip: 'native library not built at $libPath',
    );
    return;
  }

  late final NativeBackend native;
  const fb = FallbackBackend();

  final key = Uint8List.fromList([
    for (var i = 0; i < 32; i++) (i * 9 + 2) & 0xFF,
  ]);
  final nonce = Uint8List.fromList([
    for (var i = 0; i < 12; i++) (i * 4 + 1) & 0xFF,
  ]);
  final aad = Uint8List.fromList(utf8.encode('associated-data'));
  final pt = Uint8List.fromList(
    utf8.encode('cross-backend AEAD payload — 0123456789'),
  );

  setUpAll(() => native = NativeBackend.open(libPath));

  for (final alg in PqAeadAlgorithm.values) {
    group(alg.name, () {
      test('native seal/open round-trip', () {
        final ct = native.aeadSeal(alg, key, nonce, pt, aad);
        expect(ct.length, pt.length + alg.tagBytes);
        expect(native.aeadOpen(alg, key, nonce, ct, aad), equals(pt));
      });

      test(
        'cross-backend: native (AWS-LC) seal -> pqforge/PointyCastle open',
        () {
          final ct = native.aeadSeal(alg, key, nonce, pt, aad);
          expect(
            fb.aeadOpen(alg, key, nonce, ct, aad),
            equals(pt),
            reason: 'byte-level interop (native ct + tag)',
          );
        },
      );

      test(
        'cross-backend: pqforge/PointyCastle seal -> native (AWS-LC) open',
        () {
          final ct = fb.aeadSeal(alg, key, nonce, pt, aad);
          expect(
            native.aeadOpen(alg, key, nonce, ct, aad),
            equals(pt),
            reason: 'byte-level interop (fallback ct + tag)',
          );
        },
      );

      test(
        'native open of a tampered tag throws VerificationFailedException',
        () {
          final ct = native.aeadSeal(alg, key, nonce, pt, aad);
          final bad = Uint8List.fromList(ct)..[ct.length - 1] ^= 0x80;
          expect(
            () => native.aeadOpen(alg, key, nonce, bad, aad),
            throwsA(isA<VerificationFailedException>()),
          );
        },
      );
    });
  }

  test(
    'native open of a too-short input throws InvalidCiphertextException',
    () {
      expect(
        () => native.aeadOpen(
          PqAeadAlgorithm.aes256Gcm,
          key,
          nonce,
          Uint8List(8),
          aad,
        ),
        throwsA(isA<InvalidCiphertextException>()),
      );
    },
  );

  test('selector facade: AEAD through the native backend', () {
    PqForge.reset();
    addTearDown(PqForge.reset);
    final pq = PqForge.instance(nativeLibraryPath: libPath);
    expect(pq.isAccelerated, isTrue);
    final ct = pq.aeadSeal(
      PqAeadAlgorithm.chaCha20Poly1305,
      key,
      nonce,
      pt,
      aad,
    );
    expect(
      pq.aeadOpen(PqAeadAlgorithm.chaCha20Poly1305, key, nonce, ct, aad),
      equals(pt),
    );
  });
}
