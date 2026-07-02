import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:pqforge_ffi/pqforge_ffi.dart';
import 'package:test/test.dart';

const int _chunk = 64; // small frame size to exercise multi-frame logic
int get _cipherChunk => _chunk + PqAeadAlgorithm.aes256Gcm.tagBytes; // 80

/// Re-chunks [data] into [pieceSize] source events — deliberately unaligned to
/// the frame size, to prove the carry/concat buffering is event-boundary
/// independent.
Stream<List<int>> _pieces(Uint8List data, int pieceSize) async* {
  for (var i = 0; i < data.length; i += pieceSize) {
    yield Uint8List.sublistView(data, i, min(i + pieceSize, data.length));
  }
}

Future<Uint8List> _collect(Stream<Uint8List> s) async {
  final b = BytesBuilder();
  await for (final c in s) {
    b.add(c);
  }
  return b.toBytes();
}

String _libPath() {
  final name = Platform.isWindows
      ? 'pqforge_core.dll'
      : Platform.isMacOS
      ? 'libpqforge_core.dylib'
      : 'libpqforge_core.so';
  return '${Directory.current.path}/rust/target/release/$name';
}

void main() {
  const fb = FallbackBackend();
  final key = Uint8List.fromList([
    for (var i = 0; i < 32; i++) (i * 7 + 1) & 0xFF,
  ]);
  final aad = Uint8List.fromList(const [1, 2, 3, 4]);
  final rnd = Random(0xC0FFEE);
  Uint8List msg(int n) =>
      Uint8List.fromList(List.generate(n, (_) => rnd.nextInt(256)));

  Future<Uint8List> seal(
    Uint8List pt, {
    PqAeadAlgorithm alg = PqAeadAlgorithm.aes256Gcm,
    PqForgeStream s = const PqForgeStream(fb),
  }) => _collect(
    s.seal(
      _pieces(pt, 7),
      key: key,
      algorithm: alg,
      chunkSize: _chunk,
      aad: aad,
    ),
  );

  Future<Uint8List> open(
    Uint8List ct, {
    PqAeadAlgorithm alg = PqAeadAlgorithm.aes256Gcm,
    Uint8List? withKey,
    PqForgeStream s = const PqForgeStream(fb),
  }) => _collect(
    s.open(
      _pieces(ct, 13),
      key: withKey ?? key,
      algorithm: alg,
      chunkSize: _chunk,
      aad: aad,
    ),
  );

  group('streaming round-trip across many sizes', () {
    for (final alg in PqAeadAlgorithm.values) {
      for (final size in const [0, 1, 63, 64, 65, 127, 128, 129, 256, 1000]) {
        test('${alg.name} size $size', () async {
          final pt = msg(size);
          final ct = await seal(pt, alg: alg);
          expect(await open(ct, alg: alg), equals(pt));
        });
      }
    }
  });

  group('streaming integrity (200 bytes = 4 frames)', () {
    test('tampered ciphertext fails authentication', () async {
      final ct = await seal(msg(200));
      final bad = Uint8List.fromList(ct)..[10] ^= 0xFF;
      expect(() => open(bad), throwsA(isA<VerificationFailedException>()));
    });

    test(
      'truncated stream (final frame dropped) fails authentication',
      () async {
        final ct = await seal(msg(128)); // exactly 2 full frames
        final firstFrameOnly = Uint8List.sublistView(ct, 0, _cipherChunk);
        expect(
          () => open(firstFrameOnly),
          throwsA(isA<VerificationFailedException>()),
        );
      },
    );

    test('reordered frames fail authentication', () async {
      final ct = await seal(msg(128)); // 2 frames of _cipherChunk each
      final swapped = Uint8List(ct.length)
        ..setRange(0, _cipherChunk, Uint8List.sublistView(ct, _cipherChunk))
        ..setRange(
          _cipherChunk,
          ct.length,
          Uint8List.sublistView(ct, 0, _cipherChunk),
        );
      expect(() => open(swapped), throwsA(isA<VerificationFailedException>()));
    });

    test('the wrong key fails authentication', () async {
      final ct = await seal(msg(200));
      expect(
        () => open(ct, withKey: Uint8List(32)),
        throwsA(isA<VerificationFailedException>()),
      );
    });

    test('an empty ciphertext stream throws InvalidCiphertextException', () {
      expect(
        () => open(Uint8List(0)),
        throwsA(isA<InvalidCiphertextException>()),
      );
    });
  });

  final libPath = _libPath();
  if (File(libPath).existsSync()) {
    group('cross-backend streaming', () {
      final native = NativeBackend.open(libPath);
      final nativeStream = PqForgeStream(native);

      for (final alg in PqAeadAlgorithm.values) {
        for (final size in const [0, 100, 256, 1000]) {
          test('${alg.name} size $size: native seal → fallback open', () async {
            final pt = msg(size);
            final ct = await seal(pt, alg: alg, s: nativeStream);
            expect(await open(ct, alg: alg), equals(pt));
          });

          test('${alg.name} size $size: fallback seal → native open', () async {
            final pt = msg(size);
            final ct = await seal(pt, alg: alg);
            expect(await open(ct, alg: alg, s: nativeStream), equals(pt));
          });
        }
      }
    });
  } else {
    test(
      'cross-backend streaming',
      () {},
      skip: 'native library not built at $libPath',
    );
  }
}
