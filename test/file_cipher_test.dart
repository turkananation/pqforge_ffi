import 'dart:io';
import 'dart:math';
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

Future<Uint8List> _collect(Stream<Uint8List> s) async {
  final b = BytesBuilder();
  await for (final c in s) {
    b.add(c);
  }
  return b.toBytes();
}

/// Phase 3.4 (§8.4): the native zero-FFI file pipeline. The headline check is
/// **cross-layer interop** — a file sealed by the native Rust pipeline opens with
/// the Dart `PqForgeStream`, and vice-versa (identical STREAM wire format).
void main() {
  final libPath = _libPath();
  if (!File(libPath).existsSync()) {
    test(
      'native file pipeline',
      () {},
      skip: 'native library not built at $libPath',
    );
    return;
  }

  late final PqForgeFileCipher cipher;
  late final Directory dir;
  const fb = FallbackBackend();
  const dartStream = PqForgeStream(fb);
  final key = Uint8List.fromList([
    for (var i = 0; i < 32; i++) (i * 11 + 3) & 0xFF,
  ]);
  final aad = Uint8List.fromList(const [9, 8, 7]);
  final rnd = Random(2026);
  const chunk = 64;
  Uint8List msg(int n) =>
      Uint8List.fromList(List.generate(n, (_) => rnd.nextInt(256)));

  setUpAll(() async {
    cipher = PqForgeFileCipher.open(libPath);
    dir = await Directory.systemTemp.createTemp('pqforge_file_test');
  });
  tearDownAll(() async {
    if (await dir.exists()) await dir.delete(recursive: true);
  });

  var seq = 0;
  Future<String> writeFile(Uint8List data) async {
    final path = '${dir.path}/f${seq++}';
    await File(path).writeAsBytes(data, flush: true);
    return path;
  }

  String outPath() => '${dir.path}/o${seq++}';

  for (final alg in PqAeadAlgorithm.values) {
    for (final size in const [0, 1, 64, 100, 200, 1000]) {
      test(
        '${alg.name} size $size: native file seal/open round-trip',
        () async {
          final pt = msg(size);
          final inP = await writeFile(pt);
          final encP = outPath();
          final decP = outPath();
          await cipher.seal(
            inP,
            encP,
            key: key,
            algorithm: alg,
            aad: aad,
            chunkSize: chunk,
          );
          await cipher.open(
            encP,
            decP,
            key: key,
            algorithm: alg,
            aad: aad,
            chunkSize: chunk,
          );
          expect(await File(decP).readAsBytes(), equals(pt));
        },
      );

      test(
        '${alg.name} size $size: cross-layer native file seal → Dart stream open',
        () async {
          final pt = msg(size);
          final inP = await writeFile(pt);
          final encP = outPath();
          await cipher.seal(
            inP,
            encP,
            key: key,
            algorithm: alg,
            aad: aad,
            chunkSize: chunk,
          );
          final encBytes = await File(encP).readAsBytes();
          final opened = await _collect(
            dartStream.open(
              Stream.value(encBytes),
              key: key,
              algorithm: alg,
              aad: aad,
              chunkSize: chunk,
            ),
          );
          expect(
            opened,
            equals(pt),
            reason: 'native file wire format must equal the Dart STREAM format',
          );
        },
      );

      test(
        '${alg.name} size $size: cross-layer Dart stream seal → native file open',
        () async {
          final pt = msg(size);
          final ct = await _collect(
            dartStream.seal(
              Stream.value(pt),
              key: key,
              algorithm: alg,
              aad: aad,
              chunkSize: chunk,
            ),
          );
          final encP = await writeFile(ct);
          final decP = outPath();
          await cipher.open(
            encP,
            decP,
            key: key,
            algorithm: alg,
            aad: aad,
            chunkSize: chunk,
          );
          expect(await File(decP).readAsBytes(), equals(pt));
        },
      );
    }
  }

  test('a tampered file fails authentication', () async {
    final inP = await writeFile(msg(300));
    final encP = outPath();
    await cipher.seal(inP, encP, key: key, chunkSize: chunk);
    final enc = await File(encP).readAsBytes();
    enc[5] ^= 0xFF;
    await File(encP).writeAsBytes(enc, flush: true);
    await expectLater(
      cipher.open(encP, outPath(), key: key, chunkSize: chunk),
      throwsA(isA<VerificationFailedException>()),
    );
  });

  test('atomic: a failed open publishes no output file', () async {
    final inP = await writeFile(msg(200));
    final encP = outPath();
    await cipher.seal(inP, encP, key: key, chunkSize: chunk);
    final enc = await File(encP).readAsBytes();
    enc[enc.length - 1] ^= 0x80; // corrupt the final tag
    await File(encP).writeAsBytes(enc, flush: true);

    final decP = outPath();
    await expectLater(
      cipher.open(encP, decP, key: key, chunkSize: chunk),
      throwsA(isA<VerificationFailedException>()),
    );
    expect(
      await File(decP).exists(),
      isFalse,
      reason: 'output published atomically',
    );
    expect(
      await File('$decP.pqforge-tmp').exists(),
      isFalse,
      reason: 'temp cleaned up',
    );
  });

  test('a missing input file surfaces a typed error', () async {
    await expectLater(
      cipher.open(
        '${dir.path}/does-not-exist',
        outPath(),
        key: key,
        chunkSize: chunk,
      ),
      throwsA(isA<PqForgeFfiException>()),
    );
  });
}
