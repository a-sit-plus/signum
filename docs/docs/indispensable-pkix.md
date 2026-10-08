# Indispensable PKIX

The core [Indispensable](indispensable.md) module understands certificates and CSRs. This module
adds typed X.509 extensions, X.500 attributes, general names and trust-anchor data. It does not
perform signature operations or certificate path validation; those live in [PKIX Supreme](pkix-supreme.md).

Use `at.asitplus.signum:indispensable-pkix:4.0.0`.

## Install Before Decoding

Call `Signum.installPkix()` once during application startup, before accessing `Signum.Der` or
otherwise sealing the descriptor registries. It installs the typed descriptors and contextual
serializers. The examples execute under a test session that performs this startup step.
Applications adding their own descriptors must also register them before sealing; see
[Extensibility](extensibility.md).

## Typed Data

Extensions include `BasicConstraints`, `KeyUsage`, `ExtendedKeyUsage`, identifiers, certificate
policies, policy mappings/constraints, `InhibitAnyPolicy` and `NameConstraints`. Attributes include
`CommonName`, `Country`, `Organization` and the other registered X.500 types. General names include
DNS, mail, URI, directory, IP and registered-ID forms.

```kotlin
--8<-- "indispensable-pkix/src/jvmTest/kotlin/at/asitplus/signum/examples/PkixExamples.kt:pkix-typed-data"
```

1. The base `CertificateExtension` decoder dispatches to the registered type. Without a descriptor, an extension remains an uninterpreted core value.

Unknown data and malformed registered data are different: an unknown OID can be preserved as an
uninterpreted value, while a registered descriptor that recognizes an OID but cannot decode its
value reports a decoding failure. Do not silently downgrade malformed known extensions to unknown ones.
```kotlin
--8<-- "indispensable-pkix/src/jvmTest/kotlin/at/asitplus/signum/examples/PkixExamples.kt:pkix-unknown-malformed"
```

Typed values expose an awesn1 `asn1Representation`; decoded source representations are retained,
while newly constructed values have no original source. See the core encoding discussion.

## Trust Anchors and Bundled Roots

The trust APIs require `@OptIn(ExperimentalPkiApi::class)`. A `TrustAnchor` is an explicitly trusted
certificate or CA name/public-key pair, not an arbitrary final certificate received from a peer.
`TrustStore` provides anchor lookup, and `BundledTrustStore` is available on every supported target.

The bundled roots are generated at build time from Apple's open-source
[security_certificates](https://github.com/apple-oss-distributions/security_certificates) repository,
at the project's pinned `appleTrustStoreRef` (currently `security_certificates-55349.40.11`). They are a snapshot, not the live Apple system store;
build generation downloads the pinned archive when it is not cached. Review and update the pinned
source according to your application's trust policy. OS-specific EKU scoping and partial distrust are not represented: embedded certificates are treated
as fully trusted roots. Presence in a bundle does not automatically
make a root appropriate for every application.

!!! tip
    **Do check out the full API docs [here](dokka/indispensable-pkix/index.html)** for the concrete data types.
