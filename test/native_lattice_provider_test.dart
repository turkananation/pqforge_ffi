@Timeout(Duration(minutes: 3))
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqforge_ffi/pqforge_ffi.dart' show NativePqforgeLatticeProvider;
import 'package:test/test.dart';

String _libPath() {
  final name = Platform.isWindows
      ? 'pqforge_core.dll'
      : Platform.isMacOS
      ? 'libpqforge_core.dylib'
      : 'libpqforge_core.so';
  return '${Directory.current.path}/rust/target/release/$name';
}

Uint8List _pattern(int n, int Function(int) f) =>
    Uint8List.fromList(List<int>.generate(n, f));

/// Phase α: the native AWS-LC engine plugged into pqforge's swappable lattice
/// seam ([PqLattice.provider]).
///
/// Proves (1) the native provider agrees with the pure-Dart reference on every
/// deterministic operation and cross-verifies signatures, and (2) registering it
/// transparently accelerates — and stays wire-compatible with — the *whole*
/// pqforge toolkit. Skipped cleanly when the native library is absent.
void main() {
  final libPath = _libPath();
  if (!File(libPath).existsSync()) {
    test(
      'native lattice provider',
      () {},
      skip: 'native library not built at $libPath',
    );
    return;
  }

  late final NativePqforgeLatticeProvider native;
  const reference = PqPureDartLatticeProvider();

  setUpAll(() => native = NativePqforgeLatticeProvider.open(libPath));
  tearDown(PqLattice.useDefault); // never leak the swapped provider

  test('advertises its name and a pure-Dart fallback', () {
    expect(native.name, 'pqforge-ffi-awslc-lattice');
    expect(native.fallback, isA<PqPureDartLatticeProvider>());
  });

  group('KEM agrees with the pure-Dart reference', () {
    for (final kem in PqKemAlgorithm.values) {
      test(kem.name, () {
        // Seeded keygen falls through to pure-Dart => byte-identical.
        final seed = _pattern(64, (i) => (i * 5 + 2) & 0xFF);
        final (pkR, skR) = reference.kemGenerateKeyPair(kem, seed: seed);
        final (pkN, skN) = native.kemGenerateKeyPair(kem, seed: seed);
        expect(pkN, pkR, reason: 'seeded ML-KEM keygen must match pure-Dart');
        expect(skN, skR);

        // Native (randomized) keygen + an encaps/decaps round-trip.
        final (pk, sk) = native.kemGenerateKeyPair(kem);
        final (ct, ss) = native.kemEncapsulate(kem, pk);
        expect(native.kemDecapsulate(kem, sk, ct), ss);

        // Cross-impl: native decapsulates a pure-Dart ciphertext and vice-versa.
        final (ctR, ssR) = reference.kemEncapsulate(kem, pk);
        expect(
          native.kemDecapsulate(kem, sk, ctR),
          ssR,
          reason: 'native must decapsulate a pure-Dart ciphertext',
        );
        final (ctN, ssN) = native.kemEncapsulate(kem, pk);
        expect(
          reference.kemDecapsulate(kem, sk, ctN),
          ssN,
          reason: 'pure-Dart must decapsulate a native ciphertext',
        );
      });
    }
  });

  group('DSA agrees with the pure-Dart reference', () {
    for (final dsa in PqSignatureAlgorithm.values) {
      test(dsa.name, () {
        // Seeded keygen is KAT-identical across implementations.
        final seed = _pattern(32, (i) => (i * 3 + 1) & 0xFF);
        final (pkR, skR) = reference.dsaGenerateKeyPairSeeded(dsa, seed);
        final (pkN, skN) = native.dsaGenerateKeyPairSeeded(dsa, seed);
        expect(pkN, pkR, reason: 'native ML-DSA keygen-from-seed must match');
        expect(skN, skR);

        final msg = _pattern(50, (i) => (i * 5) & 0xFF);
        // A native signature verifies under the reference and vice-versa.
        final sigN = native.dsaSign(dsa, skN, msg);
        expect(sigN, hasLength(dsa.signatureBytes));
        expect(
          reference.dsaVerify(dsa, pkN, msg, sigN),
          isTrue,
          reason: 'pure-Dart must verify a native signature',
        );
        final sigR = reference.dsaSign(dsa, skR, msg);
        expect(
          native.dsaVerify(dsa, pkR, msg, sigR),
          isTrue,
          reason: 'native must verify a pure-Dart signature',
        );

        // A tampered message is rejected.
        final bad = Uint8List.fromList(msg)..[0] ^= 0x01;
        expect(native.dsaVerify(dsa, pkN, bad, sigN), isFalse);

        // Context / pre-hash variants fall through to pure-Dart on both sides.
        final ctx = _pattern(8, (i) => i & 0xFF);
        final sigCtx = native.dsaSign(dsa, skN, msg, context: ctx);
        expect(native.dsaVerify(dsa, pkN, msg, sigCtx, context: ctx), isTrue);
        expect(
          native.dsaVerify(dsa, pkN, msg, sigCtx),
          isFalse,
          reason: 'a context-bound signature must not verify without it',
        );
        final sigPre = native.dsaSign(dsa, skN, msg, preHash: true);
        expect(native.dsaVerify(dsa, pkN, msg, sigPre, preHash: true), isTrue);
      });
    }
  });

  test(
    'drop-in: registering the native provider accelerates the whole toolkit',
    () {
      PqLattice.provider = native;
      expect(PqLattice.provider.name, 'pqforge-ffi-awslc-lattice');

      const forge = PqForge(profile: PqForgeProfile.compact);
      final keys = forge.generateKeys();
      final message = _pattern(96, (i) => (i * 11) & 0xFF);

      final envelope = forge.encrypt(
        keys.kemKeyPair.publicKey,
        message,
        signerSecretKey: keys.signatureKeyPair.secretKey,
      );
      final opened = forge.decrypt(
        keys.kemKeyPair.secretKey,
        envelope,
        signerPublicKey: keys.signatureKeyPair.publicKey,
      );
      expect(
        opened,
        message,
        reason: 'a full pqforge envelope round-trips on the native engine',
      );
    },
  );

  test(
    'wire parity: an envelope sealed natively opens on the pure-Dart default',
    () {
      // Seal with the native provider registered, restore the default, then
      // decrypt — proving the accelerated path is byte-compatible on the wire.
      PqLattice.provider = native;
      const forge = PqForge(profile: PqForgeProfile.compact);
      final keys = forge.generateKeys();
      final message = _pattern(64, (i) => i & 0xFF);
      final envelope = forge.encrypt(
        keys.kemKeyPair.publicKey,
        message,
        signerSecretKey: keys.signatureKeyPair.secretKey,
      );

      PqLattice.useDefault();
      final opened = forge.decrypt(
        keys.kemKeyPair.secretKey,
        envelope,
        signerPublicKey: keys.signatureKeyPair.publicKey,
      );
      expect(opened, message);
    },
  );
}
