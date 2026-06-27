/// pqforge_ffi — hardware-accelerated, FIPS-aligned post-quantum cryptography
/// for Dart and Flutter, with a transparent pure-Dart fallback over the
/// [`pqforge`](https://pub.dev/packages/pqforge) toolkit.
///
/// ```dart
/// final pq = PqForge.instance();
/// final kp = pq.generateKemKeyPair(PqKemAlgorithm.mlKem768);
/// final enc = pq.encapsulate(PqKemAlgorithm.mlKem768, kp.publicKey);
/// final ss = pq.decapsulate(PqKemAlgorithm.mlKem768, kp.secretKey, enc.ciphertext);
/// ```
library;

// Re-export the `pqforge` vocabulary callers need, so a single import suffices.
export 'package:pqforge/pqforge.dart'
    show
        PqKemAlgorithm,
        PqSignatureAlgorithm,
        PqKeyPair,
        PqKemEncapsulation,
        PqForgeProfile;

export 'src/backend/backend.dart'
    show PqForgeBackend, BackendKind, kPqForgeAbiVersion;
export 'src/backend/fallback_backend.dart' show FallbackBackend;
export 'src/backend/native_backend.dart' show NativeBackend;
export 'src/backend/selector.dart' show PqForge;
export 'src/model/errors.dart';
