@Timeout(Duration(minutes: 3))
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqforge_ffi/pqforge_ffi.dart'
    show NativePqforgeClassicalProvider;
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

/// Phase β: the native AWS-LC engine plugged into pqforge's swappable *classical*
/// seam ([PqClassical.provider]).
///
/// Proves the native X25519 + Ed25519 paths agree with the pure-Dart reference
/// byte-for-byte (RFC 7748 / RFC 8032 are deterministic), that ECDSA-P256
/// transparently falls through to the pure-Dart fallback, and that registering
/// the provider accelerates — and stays interoperable with — the real pqforge
/// hybrid handshake. Skipped cleanly when the native library is absent.
void main() {
  final libPath = _libPath();
  if (!File(libPath).existsSync()) {
    test(
      'native classical provider',
      () {},
      skip: 'native library not built at $libPath',
    );
    return;
  }

  late final NativePqforgeClassicalProvider native;
  const reference = PqPureDartClassicalProvider();

  setUpAll(() => native = NativePqforgeClassicalProvider.open(libPath));
  tearDown(PqClassical.useDefault); // never leak the swapped provider

  test('advertises its name and a pure-Dart fallback', () {
    expect(native.name, 'pqforge-ffi-awslc-classical');
    expect(native.fallback, isA<PqPureDartClassicalProvider>());
  });

  group('X25519', () {
    test(
      'ECDH is symmetric and byte-identical to the pure-Dart reference',
      () async {
        final a = await native.x25519GenerateKeyPair();
        final b = await native.x25519GenerateKeyPair();
        expect(a.publicKey, hasLength(32));
        expect(a.secretKey, hasLength(32));
        final ssAB = await native.x25519SharedSecret(
          secretKey: a.secretKey,
          remotePublicKey: b.publicKey,
        );
        final ssBA = await native.x25519SharedSecret(
          secretKey: b.secretKey,
          remotePublicKey: a.publicKey,
        );
        expect(ssAB, ssBA, reason: 'X25519 ECDH must be symmetric');
        expect(ssAB, hasLength(32));
        // The pure-Dart provider must derive the same shared secret.
        final ssRef = await reference.x25519SharedSecret(
          secretKey: a.secretKey,
          remotePublicKey: b.publicKey,
        );
        expect(
          ssAB,
          ssRef,
          reason: 'X25519 ECDH must match the pure-Dart engine',
        );
      },
    );

    test('seeded keygen is deterministic and matches the reference', () async {
      final seed = _pattern(32, (i) => (i * 7 + 1) & 0xFF);
      final n1 = await native.x25519GenerateKeyPair(seed: seed);
      final n2 = await native.x25519GenerateKeyPair(seed: seed);
      expect(n1.publicKey, n2.publicKey);
      expect(
        n1.secretKey,
        seed,
        reason: 'the X25519 secret key is its own seed',
      );
      final ref = await reference.x25519GenerateKeyPair(seed: seed);
      expect(
        n1.publicKey,
        ref.publicKey,
        reason: 'X25519 seeded public key must match the pure-Dart engine',
      );
    });
  });

  group('Ed25519', () {
    test('sign/verify round-trips and rejects tampering', () async {
      final kp = await native.ed25519GenerateKeyPair();
      final msg = _pattern(40, (i) => i & 0xFF);
      final sig = await native.ed25519Sign(
        secretKey: kp.secretKey,
        publicKey: kp.publicKey,
        message: msg,
      );
      expect(sig, hasLength(64));
      expect(
        await native.ed25519Verify(
          publicKey: kp.publicKey,
          message: msg,
          signature: sig,
        ),
        isTrue,
      );
      final bad = Uint8List.fromList(msg)..[0] ^= 0x01;
      expect(
        await native.ed25519Verify(
          publicKey: kp.publicKey,
          message: bad,
          signature: sig,
        ),
        isFalse,
        reason: 'a tampered message must not verify',
      );
      // A wrong-length key/signature returns false (never throws).
      expect(
        await native.ed25519Verify(
          publicKey: Uint8List(10),
          message: msg,
          signature: sig,
        ),
        isFalse,
      );
    });

    test(
      'seeded keygen + signatures are byte-identical to the reference',
      () async {
        final seed = _pattern(32, (i) => (i * 3 + 2) & 0xFF);
        final n = await native.ed25519GenerateKeyPair(seed: seed);
        final r = await reference.ed25519GenerateKeyPair(seed: seed);
        expect(n.publicKey, r.publicKey, reason: 'Ed25519 keygen must match');
        expect(
          n.secretKey,
          seed,
          reason: 'the Ed25519 secret key is its own seed',
        );
        expect(await native.ed25519PublicKeyFromSeed(seed), n.publicKey);

        final msg = _pattern(33, (i) => (i * 2 + 1) & 0xFF);
        final sigN = await native.ed25519Sign(
          secretKey: n.secretKey,
          publicKey: n.publicKey,
          message: msg,
        );
        final sigR = await reference.ed25519Sign(
          secretKey: r.secretKey,
          publicKey: r.publicKey,
          message: msg,
        );
        expect(
          sigN,
          sigR,
          reason: 'Ed25519 signatures must be byte-identical (RFC 8032)',
        );
        // Cross-verify both directions.
        expect(
          await reference.ed25519Verify(
            publicKey: n.publicKey,
            message: msg,
            signature: sigN,
          ),
          isTrue,
        );
        expect(
          await native.ed25519Verify(
            publicKey: r.publicKey,
            message: msg,
            signature: sigR,
          ),
          isTrue,
        );
      },
    );
  });

  test(
    'ECDSA-P256 falls through to the pure-Dart fallback and cross-verifies',
    () async {
      final kp = await native.ecdsaP256GenerateKeyPair();
      expect(kp.publicKey, hasLength(65));
      expect(kp.secretKey, hasLength(32));
      expect(
        await native.ecdsaP256PublicKeyFromPrivate(kp.secretKey),
        kp.publicKey,
      );
      final msg = _pattern(50, (i) => (i * 5) & 0xFF);
      final sig = await native.ecdsaP256Sign(
        secretKey: kp.secretKey,
        message: msg,
      );
      expect(sig, hasLength(64));
      expect(
        await native.ecdsaP256Verify(
          publicKey: kp.publicKey,
          message: msg,
          signature: sig,
        ),
        isTrue,
      );
      // Same pure-Dart engine on both sides ⇒ the reference verifies it too.
      expect(
        await reference.ecdsaP256Verify(
          publicKey: kp.publicKey,
          message: msg,
          signature: sig,
        ),
        isTrue,
      );
    },
  );

  test(
    'drop-in: the native provider accelerates the full hybrid handshake',
    () async {
      PqClassical.provider = native;
      expect(PqClassical.provider.name, 'pqforge-ffi-awslc-classical');

      const profile = PqForgeProfile.compact;
      final forge = PqForge(profile: profile);
      final serverKem = forge.generateKemKeyPair();
      const agreement = PqForgeHybridKeyAgreement(profile: profile);
      final serverX25519 = await agreement.generateClassicalKeyPair();
      final serverX25519Public = await serverX25519.extractPublicKey();
      final deploymentSalt = Uint8List.fromList(List<int>.filled(32, 7));

      final client = await agreement.initiate(
        serverClassicalPublicKey: serverX25519Public,
        serverKemPublicKey: serverKem.publicKey,
        deploymentSalt: deploymentSalt,
      );
      final server = await agreement.accept(
        serverClassicalKeyPair: serverX25519,
        serverKemSecretKey: serverKem.secretKey,
        request: client.request,
        deploymentSalt: deploymentSalt,
      );
      expect(
        PqBytes.constantTimeEquals(client.sessionKey, server),
        isTrue,
        reason:
            'both peers derive the same session key on the native classical '
            'engine',
      );
    },
  );

  test('interop: a handshake initiated natively completes on the pure-Dart '
      'default', () async {
    // Native X25519 is byte-identical, so a session opened with the native
    // provider registered can be accepted after restoring the pure-Dart default.
    const profile = PqForgeProfile.compact;
    final forge = PqForge(profile: profile);
    final serverKem = forge.generateKemKeyPair();
    const agreement = PqForgeHybridKeyAgreement(profile: profile);

    PqClassical.provider = native;
    final serverX25519 = await agreement.generateClassicalKeyPair();
    final serverX25519Public = await serverX25519.extractPublicKey();
    final deploymentSalt = Uint8List.fromList(List<int>.filled(32, 9));
    final client = await agreement.initiate(
      serverClassicalPublicKey: serverX25519Public,
      serverKemPublicKey: serverKem.publicKey,
      deploymentSalt: deploymentSalt,
    );

    PqClassical.useDefault();
    final server = await agreement.accept(
      serverClassicalKeyPair: serverX25519,
      serverKemSecretKey: serverKem.secretKey,
      request: client.request,
      deploymentSalt: deploymentSalt,
    );
    expect(
      PqBytes.constantTimeEquals(client.sessionKey, server),
      isTrue,
      reason:
          'native-initiated session must complete on the pure-Dart '
          'default',
    );
  });
}
