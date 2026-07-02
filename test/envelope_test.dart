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

/// Phase 3.3: the single-shot KEM-DEM envelope. The pure-Dart group always runs;
/// the cross-backend group proves a native-sealed envelope opens on the fallback
/// and vice-versa.
void main() {
  const fb = FallbackBackend();
  final message = Uint8List.fromList(
    utf8.encode('Meet at the bridge at dawn. — αβ'),
  );
  final aad = Uint8List.fromList(utf8.encode('context:2026'));

  group('fallback envelope', () {
    const env = PqForgeEnvelope(fb);

    for (final alg in PqKemAlgorithm.values) {
      test('${alg.name} seal/open round-trip', () {
        final kp = fb.kemGenerate(alg);
        final sealed = env.seal(alg, kp.publicKey, message, aad: aad);
        expect(env.open(kp.secretKey, sealed, aad: aad), equals(message));
      });
    }

    test('a tampered envelope fails authentication', () {
      final kp = fb.kemGenerate(PqKemAlgorithm.mlKem768);
      final sealed = env.seal(PqKemAlgorithm.mlKem768, kp.publicKey, message);
      final bad = Uint8List.fromList(sealed)..[sealed.length - 1] ^= 0x01;
      expect(
        () => env.open(kp.secretKey, bad),
        throwsA(isA<VerificationFailedException>()),
      );
    });

    test('mismatched AAD fails authentication', () {
      final kp = fb.kemGenerate(PqKemAlgorithm.mlKem768);
      final sealed = env.seal(
        PqKemAlgorithm.mlKem768,
        kp.publicKey,
        message,
        aad: aad,
      );
      expect(
        () => env.open(
          kp.secretKey,
          sealed,
          aad: Uint8List.fromList(utf8.encode('other')),
        ),
        throwsA(isA<VerificationFailedException>()),
      );
    });

    test('the wrong recipient key fails authentication', () {
      final a = fb.kemGenerate(PqKemAlgorithm.mlKem768);
      final b = fb.kemGenerate(PqKemAlgorithm.mlKem768);
      final sealed = env.seal(PqKemAlgorithm.mlKem768, a.publicKey, message);
      // ML-KEM implicit rejection → a different shared secret → AEAD auth fails.
      expect(
        () => env.open(b.secretKey, sealed),
        throwsA(isA<VerificationFailedException>()),
      );
    });

    test('a malformed envelope throws InvalidCiphertextException', () {
      expect(
        () => env.open(Uint8List(2400), Uint8List.fromList([1, 2, 3])),
        throwsA(isA<InvalidCiphertextException>()),
      );
    });
  });

  final libPath = _libPath();
  if (File(libPath).existsSync()) {
    group('cross-backend envelope', () {
      final native = NativeBackend.open(libPath);
      final nativeEnv = PqForgeEnvelope(native);
      const fallbackEnv = PqForgeEnvelope(fb);

      for (final alg in PqKemAlgorithm.values) {
        test('${alg.name} native seal → fallback open', () {
          final kp = native.kemGenerate(alg);
          final sealed = nativeEnv.seal(alg, kp.publicKey, message, aad: aad);
          expect(
            fallbackEnv.open(kp.secretKey, sealed, aad: aad),
            equals(message),
          );
        });

        test('${alg.name} fallback seal → native open', () {
          final kp = fb.kemGenerate(alg);
          final sealed = fallbackEnv.seal(alg, kp.publicKey, message, aad: aad);
          expect(
            nativeEnv.open(kp.secretKey, sealed, aad: aad),
            equals(message),
          );
        });
      }

      test('selector facade sealEnvelope/openEnvelope via native', () {
        PqForge.reset();
        addTearDown(PqForge.reset);
        final pq = PqForge.instance(nativeLibraryPath: libPath);
        expect(pq.isAccelerated, isTrue);
        final kp = pq.generateKemKeyPair(PqKemAlgorithm.mlKem1024);
        final sealed = pq.sealEnvelope(
          PqKemAlgorithm.mlKem1024,
          kp.publicKey,
          message,
          aad: aad,
        );
        expect(
          pq.openEnvelope(kp.secretKey, sealed, aad: aad),
          equals(message),
        );
      });
    });
  } else {
    test(
      'cross-backend envelope',
      () {},
      skip: 'native library not built at $libPath',
    );
  }
}
