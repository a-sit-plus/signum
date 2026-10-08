# Migrating to Indispensable 4.0.0 and Supreme 1.0.0

This guide covers the move from Indispensable **3.26.0** and Supreme **0.16.0** to
Indispensable **4.0.0** and Supreme **1.0.0**. All examples are tested against the respective versions.

## Dependencies and imports

Use `at.asitplus.signum:indispensable:4.0.0` for the basic data structures and
`at.asitplus.signum:supreme:1.0.0` for cryptographic operations. JOSE and COSE remain separate
`indispensable-josef` and `indispensable-cosef` modules at 4.0.0.
Typed PKIX data lives in `indispensable-pkix`; certificate path construction and validation lives in
`pkix-supreme`. See their [data](indispensable-pkix.md) and [validation](pkix-supreme.md) manuals.

ASN.1 moved to [awesn1](https://github.com/a-sit-plus/awesn1). Replace dependencies on the old
`indispensable-asn1` and `indispensable-oids` modules with the appropriate awesn1 modules.
The low-level imports move from `at.asitplus.signum.indispensable.asn1` to `at.asitplus.awesn1`;
wire models live under `at.asitplus.awesn1.crypto` and `.crypto.pki`, and DER lives under
`at.asitplus.awesn1.serialization`. Signum keeps semantic cryptographic and PKI types, their serializers
and the integration registry. Do not mechanically replace semantic Signum types with wire models.

The operation contracts and DSL are now in Indispensable. Update imports as follows:

| Subject | Current package |
| --- | --- |
| Digest identifiers, providers and digest operations | `at.asitplus.signum.indispensable.digest` |
| MAC identifiers, providers and operations | `at.asitplus.signum.indispensable.mac` |
| KDF identifiers, providers and operations | `at.asitplus.signum.indispensable.kdf` |
| Signing, verification and their provider contracts | `at.asitplus.signum.indispensable.sign` |
| Agreement contracts | `at.asitplus.signum.indispensable.agree` |
| Configuration DSL | `at.asitplus.signum.dsl` |

The examples use these imports before the migration:

```kotlin
--8<-- "docs/legacy-examples/src/test/kotlin/at/asitplus/signum/examples/LegacyExamples.kt:legacy-imports"
```

After:

```kotlin
--8<-- "extensibility-test/src/jvmTest/kotlin/at/asitplus/signum/examples/ExtensibilityExamples.kt:migration-current-imports"
```

Supreme still provides operation implementations and module-specific helpers, including the ephemeral
ECDH helper under `supreme.agree` and extract/expand helpers under `supreme.kdf`.
Algorithms and provider interfaces are open to extension. An exhaustive `when` over old closed algorithm
families may now need an unsupported-algorithm branch. See [Extensibility](extensibility.md) for actual
providers, serializers and custom DSL options.

## Modulator and bridge dependencies

Signum uses the [Modulator Gradle plugin](https://github.com/a-sit-plus/modulator) to connect optional
integration modules. For example, `pkix-supreme` declares `supreme` and `indispensable-pkix` as its
*carriers*. Their published Gradle metadata identifies the bridge module that combines them.
For automatic bridge selection, apply `at.asitplus.gradle.modulator` to the consuming Kotlin Multiplatform
subproject and declare both carriers with the matching published versions in the same `api` or
`implementation` dependency scope. Signum's build currently uses Modulator **0.1.0**; that version's
consumer integration runs on KMP subprojects.

You can also declare `at.asitplus.signum:pkix-supreme:1.0.0` explicitly, which brings its carrier
dependencies through the usual Gradle dependency graph and requires no Modulator plugin in the consumer.
The `carrier(...)` declarations belong to the bridge producer's build. Module selection does not install
PKIX's serializers and descriptors: call `Signum.installPkix()` during startup as described below.

## Ephemeral signing and verification

`EphemeralKey` is retired. Create a `Signer.WithExportableKey` through the suspending `Signer.Ephemeral`
factory; export the private key if another signer configuration is needed. Signer creation and verifier
creation return the objects directly. Verification is suspending, returns `SignatureVerifier.Success`, and
throws on failure. Catch failures at the boundary where your application decides what an invalid signature means.

Before (3.26.0 / 0.16.0):

```kotlin
--8<-- "docs/legacy-examples/src/test/kotlin/at/asitplus/signum/examples/LegacyExamples.kt:legacy-signing"
```

After (4.0.0 / 1.0.0):

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-ephemeral"
```

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-verification"
```

1. A different message fails verification with the same signature.

Signing still returns `SignatureResult`: read `.signature` for the signature or handle its failure form.
`SignatureResult.Error` is removed: unexpected failures now propagate as exceptions. Expected user cancellation
still produces `SignatureResult.Failure`; `UserInitiatedCancellationReason` becomes the open
`UserInitiatedCancellation` type. This matters for callers that previously handled every signing problem
by inspecting the result.

Before:

```kotlin
--8<-- "docs/legacy-examples/src/test/kotlin/at/asitplus/signum/examples/LegacyExamples.kt:legacy-signing-result"
```

After:

```kotlin
--8<-- "extensibility-test/src/jvmTest/kotlin/at/asitplus/signum/examples/ExtensibilityExamples.kt:migration-current-signing-result"
```

Do not blanket-remove every `getOrThrow()`: symmetric operations and some secret-key APIs still return
`KmmResult`. Audit each call's actual return type. Digests, MACs, KDFs and agreement also use suspending
operation contracts; keep their calls in a suspend function or coroutine.

## Encoding and semantic types

The old `Asn1Encodable`/`Asn1Decodable` contracts become `Encodable`/`Decodable` for Signum semantic types. Encode and decode semantic types through
`Signum.Der`, which supplies the contextual serializers. PEM helpers also use that application-wide instance.
`X509Certificate` becomes `Certificate`; `Pkcs10CertificationRequest` becomes `CertificationRequest`;
`X509CertificateExtension` remains a concrete X.509 implementation of the open `CertificateExtension`
contract. The awesn1 names prefixed with `X509` denote wire models, not replacements for these semantic types.

Before:

```kotlin
--8<-- "docs/legacy-examples/src/test/kotlin/at/asitplus/signum/examples/LegacyExamples.kt:legacy-encoding"
```

After:

```kotlin
--8<-- "extensibility-test/src/jvmTest/kotlin/at/asitplus/signum/examples/ExtensibilityExamples.kt:migration-current-encoding"
```

`sourceRepresentation` is a nullable pair of an open format key and the original decoded model.
`X509` identifies the ASN.1 source. Decoding retains the source for accurate re-encoding; semantic equality
and hashing ignore it. Programmatically constructed values have no source, even after encoding.
`fromAsn1Representation` retains decoded models; attribute `fromValue` constructs a fresh semantic value.
Do not populate the source cache from a getter or serializer, and do not compare raw source models when
checking semantic equality.

## Bootstrap and registry ordering

Install modules and external contributions during startup. Optionally call `Signum.setDer` once **before**
contributing serializers. Install Supreme before provider overrides; install PKIX before using its typed
descriptors. Core installation is lazy and idempotent. Configure DER and install your extensions in this order:

```kotlin
--8<-- "extensibility-test/src/jvmTest/kotlin/at/asitplus/signum/examples/ExtensibilityExamples.kt:extension-bootstrap"
```

1. Select DER settings before contributions.
2. Register a provider together with its concrete contextual serializer.
3. Register a descriptor together with its concrete serializer.
4. Resolve DER after registration is complete.

First `Signum.Der` access seals serializer registration. Each descriptor registry separately seals on its
first lookup; combined descriptor/serializer registration needs both stores open. Provider-only registration
remains mutable. Later providers are tried first, and unsupported values should return `null` to allow fallback.
Serializer precedence is core, then the custom template, then contributions in registration order; later
contributions replace earlier serializers for the same concrete type. Configure on one thread during startup,
and avoid accessing awesn1's default DER before Signum has installed its contributions.

## JOSE and COSE: distinguish existing drift from new changes

The compact/flattened/general JWS representations already existed in 3.26.0. Moving from older examples
of `JwsSigned` to `JwsCompact` is not a new 4.0.0 break. `JwsSigned` is a deprecated compatibility API;
prefer the explicit representations. The stable baseline already expects plain payload bytes when constructing
compact JWS and already supplies typed COSE creation helpers with preserved wire data.

Before, using the stable compact JWS API:

```kotlin
--8<-- "docs/legacy-examples/src/test/kotlin/at/asitplus/signum/examples/LegacyExamples.kt:legacy-jws"
```

After, including current signature conversion and verification:

```kotlin
--8<-- "indispensable-josef/src/jvmTest/kotlin/at/asitplus/signum/examples/JoseExamples.kt:jose-jws-sign-verify"
```

1. The key map is trusted application configuration. The incoming header only supplies its lookup hint.

Before, using COSE's stable `prepare`/`create` flow:

```kotlin
--8<-- "docs/legacy-examples/src/test/kotlin/at/asitplus/signum/examples/LegacyExamples.kt:legacy-cose"
```

After:

```kotlin
--8<-- "indispensable-cosef/src/jvmTest/kotlin/at/asitplus/signum/examples/CoseExamples.kt:cose-sign-verify"
```

1. Verify with a key established independently of the received COSE object.

Serialization is not verification. Supply a trusted verification key; a key advertised in an untrusted
header is only a lookup hint. Consult the [JOSE](indispensable-josef.md) and [COSE](indispensable-cosef.md)
pages for header handling and signature formats.
