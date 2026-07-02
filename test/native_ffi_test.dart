import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:pqforge_ffi/pqforge_ffi.dart';
import 'package:test/test.dart';

// C-ABI function signatures (must mirror rust/crates/pqforge_core/src/lib.rs).
typedef _AbiVersionNative = Uint32 Function();
typedef _AbiVersionDart = int Function();
typedef _StatusEchoNative = Int32 Function(Int32);
typedef _StatusEchoDart = int Function(int);
typedef _SelftestPanicNative = Int32 Function();
typedef _SelftestPanicDart = int Function();
typedef _StatusMessageNative =
    Int32 Function(Int32, Pointer<Uint8>, Size, Pointer<Size>);
typedef _StatusMessageDart =
    int Function(int, Pointer<Uint8>, int, Pointer<Size>);

String _nativeLibPath() {
  final name = Platform.isWindows
      ? 'pqforge_core.dll'
      : Platform.isMacOS
      ? 'libpqforge_core.dylib'
      : 'libpqforge_core.so';
  return '${Directory.current.path}/rust/target/release/$name';
}

/// Phase 1b validation: exercise the real `dart:ffi` boundary against the built
/// native library. If the library is absent the suite stays green (Phase 1a
/// invariant: pqforge_ffi works with no native binary). Build it with:
///   (cd rust && cargo build --release)
void main() {
  final libPath = _nativeLibPath();
  if (!File(libPath).existsSync()) {
    test(
      'native FFI smoke test',
      () {},
      skip: 'native library not built at $libPath',
    );
    return;
  }

  late final DynamicLibrary lib;
  late final _AbiVersionDart abiVersion;
  late final _StatusEchoDart statusEcho;
  late final _SelftestPanicDart selftestPanic;
  late final _StatusMessageDart statusMessage;

  setUpAll(() {
    lib = DynamicLibrary.open(libPath);
    abiVersion = lib.lookupFunction<_AbiVersionNative, _AbiVersionDart>(
      'pqforge_abi_version',
    );
    statusEcho = lib.lookupFunction<_StatusEchoNative, _StatusEchoDart>(
      'pqforge_status_echo',
    );
    selftestPanic = lib
        .lookupFunction<_SelftestPanicNative, _SelftestPanicDart>(
          'pqforge_selftest_panic',
        );
    statusMessage = lib
        .lookupFunction<_StatusMessageNative, _StatusMessageDart>(
          'pqforge_status_message',
        );
  });

  test('native ABI version matches kPqForgeAbiVersion', () {
    expect(abiVersion(), kPqForgeAbiVersion);
  });

  test('status codes round-trip through the shared taxonomy', () {
    expect(
      statusEcho(PqForgeErrorCode.invalidKey.value),
      PqForgeErrorCode.invalidKey.value,
    );
    expect(
      statusEcho(PqForgeErrorCode.bufferTooSmall.value),
      PqForgeErrorCode.bufferTooSmall.value,
    );
    // An unknown code folds to internal — identical to Dart's fromValue rule.
    expect(statusEcho(999), PqForgeErrorCode.internal.value);
    expect(
      PqForgeErrorCode.fromValue(statusEcho(999)),
      PqForgeErrorCode.internal,
    );
  });

  test('a Rust panic cannot cross FFI: returns internal, process survives', () {
    expect(selftestPanic(), PqForgeErrorCode.internal.value);
    // Reaching here at all proves the panic did not unwind across the boundary
    // (that would have aborted the VM); confirm the library is still callable.
    expect(abiVersion(), kPqForgeAbiVersion);
  });

  test('status_message writes the name and returns ok', () {
    final buf = calloc<Uint8>(64);
    final lenPtr = calloc<Size>();
    try {
      final rc = statusMessage(
        PqForgeErrorCode.invalidKey.value,
        buf,
        64,
        lenPtr,
      );
      expect(rc, PqForgeErrorCode.ok.value);
      final name = String.fromCharCodes(buf.asTypedList(lenPtr.value));
      expect(name, 'invalid_key');
    } finally {
      calloc.free(buf);
      calloc.free(lenPtr);
    }
  });

  test('status_message reports buffer_too_small with the required length', () {
    final small = calloc<Uint8>(2);
    final lenPtr = calloc<Size>();
    try {
      final rc = statusMessage(
        PqForgeErrorCode.invalidKey.value,
        small,
        2,
        lenPtr,
      );
      expect(rc, PqForgeErrorCode.bufferTooSmall.value);
      expect(lenPtr.value, 'invalid_key'.length);
    } finally {
      calloc.free(small);
      calloc.free(lenPtr);
    }
  });

  test('status_message rejects a null out_len pointer', () {
    final buf = calloc<Uint8>(64);
    try {
      final rc = statusMessage(
        PqForgeErrorCode.invalidKey.value,
        buf,
        64,
        nullptr,
      );
      expect(rc, PqForgeErrorCode.nullArgument.value);
    } finally {
      calloc.free(buf);
    }
  });
}
