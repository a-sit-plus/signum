# Migration from Signum 3.19

This guide explains how to migrate from Signum `3.19.x` to the current state of this branch, currently published as `3.20-SNAPSHOT` / `Supreme 0.12-SNAPSHOT`.

It is not a changelog summary. It is a migration document for existing consumers, and it is written to stand on its own.

## Executive summary

There are two major migration themes:

1. the ASN.1 implementation moved out of Signum into the dedicated `awesn1` modules
2. many formerly closed, enum-like or sealed-style algorithm surfaces are now intentionally extensible
3. package regrouping moved several public types into more specific subpackages

The second point is the more important semantic change.

If your code assumed that types such as `SignatureAlgorithm`, `MessageAuthenticationCode`, `SymmetricEncryptionAlgorithm`, `AsymmetricEncryptionAlgorithm`, `JwsAlgorithm`, `CoseAlgorithm`, `X509SignatureAlgorithm`, or their nested families were closed sets, you must revisit that code.

Signum now supports third-party algorithm definitions and mapping registration. That means:

- `entries` is now the canonical way to enumerate built-ins plus custom registrations
- exhaustive `when` expressions over these types are no longer a safe design assumption
- custom algorithms will not automatically get JWS, COSE, X.509, JCA, or platform mappings unless you register them

Package cleanup in this branch affects `indispensable`, `indispensable-josef`, and `indispensable-cosef`. The `supreme` module is intentionally not being reorganized.

## Version and module overview

The current branch state is:

- `indispensableVersion=3.20-SNAPSHOT`
- `supremeVersion=0.12-SNAPSHOT`

Relevant Gradle setup:

- [gradle.properties](/Users/bpruenster/Documents/0000_OSS/signum/gradle.properties)
- [indispensable/build.gradle.kts](/Users/bpruenster/Documents/0000_OSS/signum/indispensable/build.gradle.kts)
- [indispensable-asn1/build.gradle.kts](/Users/bpruenster/Documents/0000_OSS/signum/indispensable-asn1/build.gradle.kts)

Current dependency structure:

- `indispensable` re-exports `at.asitplus.awesn1:core`
- `indispensable` re-exports `at.asitplus.awesn1:crypto`
- `indispensable` re-exports `at.asitplus.awesn1:io`
- `indispensable` re-exports `at.asitplus.awesn1:oids`
- `indispensable-asn1` is now primarily a compatibility facade on top of `awesn1`

## Package hierarchy cleanup in `indispensable`, `indispensable-josef`, and `indispensable-cosef`

The `indispensable` module historically accumulated many unrelated types directly in the root package:

```kotlin
at.asitplus.signum.indispensable
```

This branch now performs a real regrouping. The goals are:

- make package ownership clearer
- keep source compatibility where Kotlin allows it through deprecated outer aliases and forwarding APIs
- document the cases where nested old names cannot be preserved cleanly

Current scope:

- `indispensable`
  - `PublicKey` -> `at.asitplus.signum.indispensable.key.PublicKey`
  - `PrivateKey` -> `at.asitplus.signum.indispensable.key.PrivateKey`
  - `Signature` -> `at.asitplus.signum.indispensable.signature.Signature`
  - `ECCurve` -> `at.asitplus.signum.indispensable.ec.ECCurve`
  - `ECPoint` -> `at.asitplus.signum.indispensable.ec.ECPoint`
  - `Attestation`, `SelfAttestation`, `AndroidKeystoreAttestation`, `IosHomebrewAttestation` -> `at.asitplus.signum.indispensable.attestation.*`
- `indispensable-josef`
  - `JsonWebAlgorithm` -> `at.asitplus.signum.indispensable.josef.algorithm.JsonWebAlgorithm`
  - `JwsAlgorithm` -> `at.asitplus.signum.indispensable.josef.algorithm.JwsAlgorithm`
  - `JweAlgorithm` -> `at.asitplus.signum.indispensable.josef.algorithm.JweAlgorithm`
- `indispensable-cosef`
  - `CoseAlgorithm` -> `at.asitplus.signum.indispensable.cosef.algorithm.CoseAlgorithm`

The old outer names remain as deprecated typealiases in their previous packages where that is possible.

The cleanup intentionally excludes `supreme`. `supreme` package structure is unchanged.

### What remains source-compatible

These old imports still compile for the outer type names and will give deprecation-guided IDE migration:

```kotlin
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.PrivateKey
import at.asitplus.signum.indispensable.Signature
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.ECPoint
import at.asitplus.signum.indispensable.Attestation

import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebAlgorithm

import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
```

### What cannot be preserved via typealias

Kotlin does not preserve nested members reliably through deprecated typealiases once the outer type moves packages. That means old nested names must be migrated manually.

Important examples:

- `at.asitplus.signum.indispensable.PublicKey.EC`
- `at.asitplus.signum.indispensable.PrivateKey.WithPublicKey`
- `at.asitplus.signum.indispensable.Signature.EC`
- `at.asitplus.signum.indispensable.Signature.RawByteEncodable`
- `at.asitplus.signum.indispensable.josef.JwsAlgorithm.Signature`
- `at.asitplus.signum.indispensable.josef.JwsAlgorithm.MAC`
- `at.asitplus.signum.indispensable.josef.JweAlgorithm.Symmetric`
- `at.asitplus.signum.indispensable.cosef.CoseAlgorithm.Signature`
- `at.asitplus.signum.indispensable.cosef.CoseAlgorithm.MAC`
- `at.asitplus.signum.indispensable.cosef.CoseAlgorithm.Symmetric`
- `at.asitplus.signum.indispensable.cosef.CoseAlgorithm.SymmetricEncryption`

For these names, update imports to the relocated outer type package.

### Recommended import rewrites

Before:

```kotlin
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.Signature
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
```

After:

```kotlin
import at.asitplus.signum.indispensable.key.PublicKey
import at.asitplus.signum.indispensable.signature.Signature
import at.asitplus.signum.indispensable.ec.ECCurve
import at.asitplus.signum.indispensable.josef.algorithm.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.algorithm.JweAlgorithm
import at.asitplus.signum.indispensable.cosef.algorithm.CoseAlgorithm
```

### Example: nested type migration

Before:

```kotlin
val key: at.asitplus.signum.indispensable.PublicKey.EC = ...
val alg: at.asitplus.signum.indispensable.josef.JwsAlgorithm.Signature = ...
```

After:

```kotlin
val key: at.asitplus.signum.indispensable.key.PublicKey.EC = ...
val alg: at.asitplus.signum.indispensable.josef.algorithm.JwsAlgorithm.Signature = ...
```

### `Attestation` import migration

Before:

```kotlin
import at.asitplus.signum.indispensable.Attestation
import at.asitplus.signum.indispensable.AndroidKeystoreAttestation
import at.asitplus.signum.indispensable.IosHomebrewAttestation
import at.asitplus.signum.indispensable.SelfAttestation
```

After:

```kotlin
import at.asitplus.signum.indispensable.attestation.Attestation
import at.asitplus.signum.indispensable.attestation.AndroidKeystoreAttestation
import at.asitplus.signum.indispensable.attestation.IosHomebrewAttestation
import at.asitplus.signum.indispensable.attestation.SelfAttestation
```

The old imports still compile through deprecated aliases. Migrate the imports when convenient.

### `PublicKey`, `PrivateKey`, `Signature`, and EC import migration

Before:

```kotlin
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.PrivateKey
import at.asitplus.signum.indispensable.Signature
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.ECPoint
```

After:

```kotlin
import at.asitplus.signum.indispensable.key.PublicKey
import at.asitplus.signum.indispensable.key.PrivateKey
import at.asitplus.signum.indispensable.signature.Signature
import at.asitplus.signum.indispensable.ec.ECCurve
import at.asitplus.signum.indispensable.ec.ECPoint
```

### `JWS`, `JWE`, and `COSE` algorithm import migration

Before:

```kotlin
import at.asitplus.signum.indispensable.josef.JsonWebAlgorithm
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
```

After:

```kotlin
import at.asitplus.signum.indispensable.josef.algorithm.JsonWebAlgorithm
import at.asitplus.signum.indispensable.josef.algorithm.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.algorithm.JweAlgorithm
import at.asitplus.signum.indispensable.cosef.algorithm.CoseAlgorithm
```

## The largest source migration: ASN.1 moved to `awesn1`

This is the biggest import-level change.

### What changed

Most ASN.1 primitives and encode/decode helpers that used to be imported from:

```kotlin
at.asitplus.signum.indispensable.asn1
```

now live in:

```kotlin
at.asitplus.awesn1
at.asitplus.awesn1.encoding
at.asitplus.awesn1.crypto
```

Signum still provides compatibility wrappers in:

- [CompatibilityFacade.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable-asn1/src/commonMain/kotlin/at/asitplus/signum/indispensable/asn1/CompatibilityFacade.kt)
- [CompatibilityConvenience.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable/src/commonMain/kotlin/at/asitplus/signum/indispensable/CompatibilityConvenience.kt)

Those wrappers are deprecated. Treat them as temporary migration aids, not as the target API.

### Typical import rewrites

Before:

```kotlin
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.PemEncodable
import at.asitplus.signum.indispensable.asn1.encodeToDer
import at.asitplus.signum.indispensable.asn1.decodeFromDer
```

After:

```kotlin
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.PemEncodable
import at.asitplus.awesn1.encoding.encodeToDer
import at.asitplus.awesn1.encoding.decodeFromDer
```

### Helper function moves

The important change is the import source, not the call style.

If you import the `awesn1` extensions, you can and should still write:

```kotlin
val der = myValue.encodeToDer()
```

What changed is that the extension now comes from `awesn1` instead of the deprecated Signum ASN.1 compatibility package.

Move these helper imports to `awesn1`:

- `encodeToDer()` -> `at.asitplus.awesn1.encoding.encodeToDer(...)`
- `decodeFromDer()` -> `at.asitplus.awesn1.encoding.decodeFromDer(...)`
- `encodeToDerOrNull()` -> `at.asitplus.awesn1.encoding.encodeToDerOrNull(...)`
- `decodeFromDerOrNull()` -> `at.asitplus.awesn1.encoding.decodeFromDerOrNull(...)`
- `encodeToTlvOrNull()` -> `at.asitplus.awesn1.encoding.encodeToTlvOrNull(...)`
- `decodeFromTlvOrNull()` -> `at.asitplus.awesn1.decodeFromTlvOrNull(...)`
- `encodeToPEM()` / `encodeToPem()` -> `at.asitplus.awesn1.encodeToPem(...)`
- `decodeFromPem()` -> `at.asitplus.awesn1.decodeFromPem(...)`

### OID description loading

If you previously used:

```kotlin
KnownOIDs.describeAll()
```

via Signum ASN.1 compatibility imports, migrate to:

```kotlin
at.asitplus.awesn1.KnownOIDs.describeAll()
```

The Signum extension in [OidExtensions.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable-oids/src/commonMain/kotlin/OidExtensions.kt) is deprecated.

## The crucial semantic migration: Signum is now extensible

This branch deliberately moves away from the older mental model of "fixed closed sets".

The relevant base abstractions are now built around:

- [Enumerable.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable-asn1/src/commonMain/kotlin/at/asitplus/signum/Enumerable.kt)
- [AlgorithmRegistry.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable/src/commonMain/kotlin/at/asitplus/signum/indispensable/AlgorithmRegistry.kt)
- [AlgorithmTraits.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable/src/commonMain/kotlin/at/asitplus/signum/indispensable/AlgorithmTraits.kt)

### Old mental model

In `3.19.x`, many consumers effectively treated algorithm families as if they were enums or permanently sealed taxonomies:

- "all supported values are built in"
- "a `when` over all known constants is exhaustive in practice"
- "mapping to JOSE / COSE / X.509 is part of the type itself"

That assumption is no longer valid.

### New mental model

Algorithm families are now open for extension.

Examples:

- [SignatureAlgorithm.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable/src/commonMain/kotlin/at/asitplus/signum/indispensable/SignatureAlgorithm.kt)
- [MessageAuthenticationCode.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable/src/commonMain/kotlin/at/asitplus/signum/indispensable/MessageAuthenticationCode.kt)
- [SymmetricEncryptionAlgorithm.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable/src/commonMain/kotlin/at/asitplus/signum/indispensable/symmetric/SymmetricEncryptionAlgorithm.kt)
- [AsymmetricEncryptionAlgorithm.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable/src/commonMain/kotlin/at/asitplus/signum/indispensable/asymmetric/AsymmetricEncryptionAlgorithm.kt)
- [JwsAlgorithm.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable-josef/src/commonMain/kotlin/at/asitplus/signum/indispensable/josef/JwsAlgorithm.kt)
- [CoseAlgorithm.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable-cosef/src/commonMain/kotlin/at/asitplus/signum/indispensable/cosef/CoseAlgorithm.kt)

Built-ins are still provided as companion properties such as:

- `SignatureAlgorithm.ECDSA_SHA256`
- `MessageAuthenticationCode.HMAC_SHA256`
- `SymmetricEncryptionAlgorithm.AES_256_GCM`
- `AsymmetricEncryptionAlgorithm.RSA_OAEP_SHA256`

But those are no longer the only valid instances.

### What this means for your code

You should update any code that does one of the following:

- assumes only built-ins exist
- hardcodes a complete list manually
- uses `when` as if it were future-proof
- throws on "unknown" values simply because they are not built-ins
- derives protocol mappings by checking for concrete built-in singleton instances only

## `Enumerable` and `entries`

The enumeration contract is now explicit:

- types implement `Enumerable`
- the companion object implements `Enumeration<T>`
- companion `entries` returns the current registered universe, not only built-ins

See [Enumerable.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable-asn1/src/commonMain/kotlin/at/asitplus/signum/Enumerable.kt).

### Important consequence

`entries` is runtime-backed.

It may contain:

- built-in Signum instances
- instances registered by your application
- instances registered by libraries you use

So do not assume:

- stable ordering
- stable size
- built-in-only membership

### Migration pattern

Before:

```kotlin
val supported = listOf(
    SignatureAlgorithm.ECDSA_SHA256,
    SignatureAlgorithm.ECDSA_SHA384,
    SignatureAlgorithm.ECDSA_SHA512,
)
```

After:

```kotlin
val supported = SignatureAlgorithm.entries
```

If you only want built-ins, there is no generic "built-ins only" contract. You must define that policy yourself.

## Exhaustive `when` expressions are not a safe design anymore

This is the most common conceptual migration bug.

### Problem

Code like this may still compile:

```kotlin
when (algorithm) {
    SignatureAlgorithm.ECDSA_SHA256 -> ...
    SignatureAlgorithm.ECDSA_SHA384 -> ...
    SignatureAlgorithm.ECDSA_SHA512 -> ...
    SignatureAlgorithm.RSA_SHA256_PKCS1 -> ...
    SignatureAlgorithm.RSA_SHA384_PKCS1 -> ...
    SignatureAlgorithm.RSA_SHA512_PKCS1 -> ...
    else -> error("unsupported")
}
```

But it is no longer future-proof. A third-party registered algorithm is now a normal, supported value of that type.

### Recommended replacement

Prefer capability- or trait-based logic:

```kotlin
when {
    algorithm is EcdsaSignatureAlgorithm -> {
        val digest = algorithm.digest
        val curve = algorithm.requiredCurve
        // handle ECDSA generically
    }
    algorithm is RsaSignatureAlgorithm -> {
        val digest = algorithm.digest
        val padding = algorithm.padding
        // handle RSA generically
    }
    else -> {
        // either reject explicitly, or consult your own extension registry/policy
    }
}
```

For many integrations, even this should be replaced with mapping lookup through `AlgorithmRegistry`, described below.

## Old types vs new extension-friendly types

A few key examples:

### Signature algorithms

Current shape:

- `SignatureAlgorithm` is an interface
- built-ins are instances of `EcdsaSignatureAlgorithm` and `RsaSignatureAlgorithm`
- legacy nested interfaces `SignatureAlgorithm.ECDSA` and `.RSA` still exist, but are deprecated compatibility surfaces

Preferred construction:

```kotlin
val custom = EcdsaSignatureAlgorithm(Digest.SHA256, requiredCurve = null)
```

not:

```kotlin
SignatureAlgorithm.ECDSA(...)
```

### MAC algorithms

Current shape:

- `MessageAuthenticationCode` is open for custom implementations
- built-in HMAC values are instances of `HmacAlgorithm`
- truncation is represented by `TruncatedMessageAuthenticationCode`

### Symmetric encryption

Current shape:

- `SymmetricEncryptionAlgorithm` is an interface hierarchy
- built-ins are provided through companion namespaces such as `AES_128`, `AES_256_GCM`, `ChaCha20Poly1305`
- custom algorithms can implement the relevant capability interfaces directly

### Asymmetric encryption

Current shape:

- `AsymmetricEncryptionAlgorithm` is open for registration
- RSA paddings are separate extensible values
- built-ins use `RsaEncryptionAlgorithm` plus `RsaEncryptionPadding`

## How to register custom algorithms

Registration is done via [AlgorithmRegistry.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable/src/commonMain/kotlin/at/asitplus/signum/indispensable/AlgorithmRegistry.kt).

The registry stores:

- custom algorithm instances
- protocol mappings
- raw X.509 mappings
- platform-specific mappings

### Registering a custom signature algorithm

Minimal example:

```kotlin
val custom = object : SignatureAlgorithm {
    override fun toString() = "CustomSignatureAlgorithm"
}

SignatureAlgorithm.register(custom)
```

After registration:

- `custom in SignatureAlgorithm.entries`
- `custom in DataIntegrityAlgorithm.entries`

This is verified in [AlgorithmRegistryTest.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable/src/jvmTest/kotlin/at/asitplus/signum/indispensable/AlgorithmRegistryTest.kt).

### Registering a custom MAC

```kotlin
val custom = object : MessageAuthenticationCode {
    override val outputLength = 128.bit
    override fun toString() = "CustomMacAlgorithm"
}

AlgorithmRegistry.registerMessageAuthenticationCode(custom)
```

### Registering a custom symmetric encryption algorithm

```kotlin
val custom =
    object : SymmetricEncryptionAlgorithm.Unauthenticated<NonceTrait.Without>,
        SymmetricEncryptionAlgorithm.WithoutNonce<AuthCapability.Unauthenticated, KeyType.Integrated> {
        override val oid = ObjectIdentifier("1.3.6.1.4.1.55555.1")
        override val name = "CustomSymmetricAlgorithm"
        override val keySize = 128.bit
        override fun toString() = name
    }

AlgorithmRegistry.registerSymmetricEncryptionAlgorithm(custom)
```

### Registering a custom asymmetric encryption algorithm

```kotlin
val customPadding = object : RsaEncryptionPadding {
    override fun toString() = "CUSTOM"
}

val customAlgorithm = RsaEncryptionAlgorithm(customPadding)

AlgorithmRegistry.registerAsymmetricRsaPadding(customPadding)
AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(customAlgorithm)
```

## Registration does not imply protocol support

This is critical.

Registering a custom Signum algorithm only makes it part of the Signum algorithm universe. It does not automatically make it:

- serializable as JWS
- serializable as COSE
- usable as an X.509 signature algorithm
- supported by JCA
- supported by iOS/macOS `SecKey`
- supported by Supreme signers/verifiers

If your code calls:

- `toJwsAlgorithm()`
- `toCoseAlgorithm()`
- X.509 conversion helpers
- JCA / platform conversion helpers

then you must register the corresponding mapping as well.

The negative tests in:

- [UnsupportedAlgorithmConversionTests.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable-cosef/src/jvmTest/kotlin/UnsupportedAlgorithmConversionTests.kt)

show the expected behavior: custom algorithms without mappings fail with `UnsupportedCryptoException`.

## How protocol mapping works

Signum now separates:

1. the abstract algorithm
2. its representation in a given protocol or platform

This is mediated through `AlgorithmRegistry` namespaces and mapping keys.

The relevant registry APIs are:

- `registerSignatureMapping(...)`
- `registerMacMapping(...)`
- `registerSymmetricMapping(...)`
- `registerAsymmetricMapping(...)`
- `registerX509SignatureMapping(...)`

### Mapping keys

See [AlgorithmTraits.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable/src/commonMain/kotlin/at/asitplus/signum/indispensable/AlgorithmTraits.kt).

These keys express semantic identity, for example:

- digest
- curve
- RSA padding
- key size
- output length

This is how Signum can map not only exact object instances, but also algorithm families with equivalent semantics.

## Extending JWS support

JWS is now represented by extensible classes in:

- [JwsAlgorithm.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable-josef/src/commonMain/kotlin/at/asitplus/signum/indispensable/josef/JwsAlgorithm.kt)

Notable changes:

- `JwsAlgorithm` is an open class, not a closed set
- `JwsAlgorithm.Signature` and `JwsAlgorithm.MAC` are open classes
- they have their own `register(...)` functions
- conversion from Signum algorithms uses `AlgorithmRegistry`

### Example: add a custom JWS MAC mapping

```kotlin
val customMac = object : MessageAuthenticationCode {
    override val outputLength = 128.bit
    override fun toString() = "CustomMac"
}

AlgorithmRegistry.registerMessageAuthenticationCode(customMac)

val customJws = JwsAlgorithm.MAC.register(
    JwsAlgorithm.MAC("HS-CUSTOM", customMac)
)

AlgorithmRegistry.registerMacMapping(
    namespace = "jws.mac",
    algorithm = customMac,
    target = customJws
)
```

After that:

- `JwsAlgorithm.fromIdentifier("HS-CUSTOM")` can resolve the JWS value
- `customMac.toJwsAlgorithm()` can succeed

### Example: add a custom JWS signature mapping

```kotlin
val customSig = object : SignatureAlgorithm {
    override fun toString() = "CustomSignature"
}

SignatureAlgorithm.register(customSig)

val customJws = JwsAlgorithm.Signature.register(
    JwsAlgorithm.Signature(
        identifier = "CS256",
        algorithm = customSig,
        rawSignatureDecoder = { bytes -> Signature.RSA(bytes) }
    )
)

AlgorithmRegistry.registerSignatureMapping(
    namespace = "jws.signature",
    algorithm = customSig,
    target = customJws
)
```

Note that `rawSignatureDecoder` must match the raw signature encoding used by that JWS algorithm.

## Extending COSE support

COSE is likewise extensible:

- [CoseAlgorithm.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable-cosef/src/commonMain/kotlin/at/asitplus/signum/indispensable/cosef/CoseAlgorithm.kt)

Notable changes:

- `CoseAlgorithm.Signature`, `.MAC`, and `.SymmetricEncryption` are open classes
- each family has a `register(...)` function
- mapping from Signum algorithms to COSE values is registry-based

### Example: add a custom COSE MAC

```kotlin
val customMac = object : MessageAuthenticationCode {
    override val outputLength = 128.bit
    override fun toString() = "CustomMac"
}

AlgorithmRegistry.registerMessageAuthenticationCode(customMac)

val customCose = CoseAlgorithm.MAC.register(
    CoseAlgorithm.MAC(
        value = -70001,
        algorithm = customMac,
        displayName = "CUSTOM_MAC"
    )
)

AlgorithmRegistry.registerMacMapping(
    namespace = "cose.mac",
    algorithm = customMac,
    target = customCose
)
```

### Example: add a custom COSE symmetric algorithm

```kotlin
val customSymmetric =
    object : SymmetricEncryptionAlgorithm.Unauthenticated<NonceTrait.Without>,
        SymmetricEncryptionAlgorithm.WithoutNonce<AuthCapability.Unauthenticated, KeyType.Integrated> {
        override val oid = ObjectIdentifier("1.3.6.1.4.1.55555.99")
        override val name = "CustomWrap"
        override val keySize = 128.bit
        override fun toString() = name
    }

AlgorithmRegistry.registerSymmetricEncryptionAlgorithm(customSymmetric)

val customCose = CoseAlgorithm.SymmetricEncryption.register(
    CoseAlgorithm.SymmetricEncryption(
        coseValue = -70002,
        algorithm = customSymmetric,
        displayName = "CUSTOM_WRAP"
    )
)

AlgorithmRegistry.registerSymmetricMapping(
    namespace = "cose.symmetric",
    algorithm = customSymmetric,
    target = customCose
)
```

## Extending X.509 signature handling

Raw X.509 signature algorithm identifiers are now based on:

- `at.asitplus.awesn1.crypto.SignatureAlgorithmIdentifier`

See:

- [X509SignatureAlgorithm.kt](/Users/bpruenster/Documents/0000_OSS/signum/indispensable/src/commonMain/kotlin/at/asitplus/signum/indispensable/X509SignatureAlgorithm.kt)

### Important migration

`X509SignatureAlgorithmDescription` is now a deprecated alias for `SignatureAlgorithmIdentifier`.

Before:

```kotlin
val raw: X509SignatureAlgorithmDescription = certificate.signatureAlgorithm
```

After:

```kotlin
val raw: SignatureAlgorithmIdentifier = certificate.signatureAlgorithm
```

### Registering a custom X.509 signature mapping

If you introduce a custom signature algorithm and want raw X.509 identifiers to resolve to it, register both:

1. the custom Signum algorithm
2. the raw X.509 mapping

Example:

```kotlin
val customSig = object : SignatureAlgorithm {
    override fun toString() = "CustomSignature"
}

SignatureAlgorithm.register(customSig)

AlgorithmRegistry.registerX509SignatureMapping(
    raw = SignatureAlgorithmIdentifier(
        oid = ObjectIdentifier("1.2.3.4.5"),
        parameters = emptyList()
    ),
    algorithm = customSig
)
```

Without this mapping, `requireSupported()` / `requireSignatureAlgorithm()` on that raw identifier will fail.

## Built-in constants are still available, but they are not the model anymore

The built-ins remain convenient entry points:

- `SignatureAlgorithm.ECDSA_SHA256`
- `MessageAuthenticationCode.HMAC_SHA256`
- `JwsAlgorithm.Signature.ES256`
- `CoseAlgorithm.MAC.HS256`

But you should stop thinking of them as enum members.

They are named, reusable built-in instances participating in a broader registry-backed universe.

## Deprecated compatibility namespaces you should phase out

Some examples:

- deprecated nested algorithm namespaces such as `SignatureAlgorithm.ECDSA(...)` and `.RSA(...)`
- deprecated aliases like `RSAPadding`
- deprecated older helper names and compatibility wrappers around ASN.1 helpers

Where possible, migrate to the concrete open classes:

- `EcdsaSignatureAlgorithm`
- `RsaSignatureAlgorithm`
- `HmacAlgorithm`
- `RsaEncryptionAlgorithm`
- `RsaSignaturePadding`
- `RsaEncryptionPadding`

## Supreme migration notes

Supreme still mostly works through the same high-level concepts:

- signers
- verifiers
- ephemeral keys
- provider-backed keys

But the new extensibility model means you should not assume every `SignatureAlgorithm` seen by Supreme is one of the built-ins.

### Safe integration style

Prefer using the provided conversion and factory APIs:

- `SignatureAlgorithm.signerFor(...)`
- `SignatureAlgorithm.verifierFor(...)`
- `SignatureAlgorithm.platformVerifierFor(...)`

instead of switching on built-in constants yourself.

### What happens for unsupported custom algorithms

Custom algorithm registration does not automatically grant Supreme execution support.

If there is no platform or Kotlin implementation behind a registered custom algorithm, factories will still fail, and that is expected.

Registration means:

- the algorithm is representable inside Signum
- it participates in enumeration and mapping

It does not mean:

- the algorithm can be executed by Supreme

## Practical migration checklist

### Step 1: move ASN.1 imports to `awesn1`

Replace imports first. This is the highest-signal low-risk migration.

### Step 2: remove assumptions that algorithm families are closed

Review any code that:

- hardcodes all supported algorithm values
- uses large `when` chains over built-ins
- serializes/deserializes by checking only known constants

### Step 3: switch enumeration logic to `entries`

Use:

- `SignatureAlgorithm.entries`
- `MessageAuthenticationCode.entries`
- `SymmetricEncryptionAlgorithm.entries`
- `AsymmetricEncryptionAlgorithm.entries`
- `JwsAlgorithm.entries`
- `CoseAlgorithm.entries`

### Step 4: migrate to concrete extensible classes

Prefer:

- `EcdsaSignatureAlgorithm`
- `RsaSignatureAlgorithm`
- `HmacAlgorithm`
- `RsaEncryptionAlgorithm`

over deprecated legacy constructor-style compatibility helpers.

### Step 5: add explicit mappings for your custom algorithms

If you have custom algorithms, decide which of these you need:

- Signum registration only
- JWS mapping
- COSE mapping
- X.509 mapping
- platform mapping

Register each explicitly.

### Step 6: treat unsupported conversions as normal

A custom algorithm with no JWS or COSE mapping should fail conversion. That is not a bug.

## Quick reference

| Old assumption | New model |
| --- | --- |
| Algorithm families are effectively closed | Algorithm families are extensible |
| Built-ins define the whole universe | Built-ins are only the default registrations |
| Manual built-in lists are acceptable | Use `entries` for runtime enumeration |
| Protocol mapping is implicit | Protocol mapping must be registered |
| ASN.1 lives under Signum | ASN.1 now lives in `awesn1` |
| `X509SignatureAlgorithmDescription` is the raw model | `SignatureAlgorithmIdentifier` is the raw model |

## Minimal before/after examples

### Before: built-in only mindset

```kotlin
fun toLabel(algorithm: SignatureAlgorithm) = when (algorithm) {
    SignatureAlgorithm.ECDSA_SHA256 -> "ES256"
    SignatureAlgorithm.ECDSA_SHA384 -> "ES384"
    SignatureAlgorithm.ECDSA_SHA512 -> "ES512"
    else -> error("unsupported")
}
```

### After: registry-aware mindset

```kotlin
fun toLabel(algorithm: SignatureAlgorithm): String =
    algorithm.toJwsAlgorithm().getOrElse {
        "unmapped:${algorithm}"
    }.identifier
```

### Before: Signum ASN.1 helper imports

```kotlin
import at.asitplus.signum.indispensable.asn1.encodeToDer

val der = myValue.encodeToDer()
```

### After: `awesn1` helper imports

```kotlin
import at.asitplus.awesn1.encoding.encodeToDer

val der = myValue.encodeToDer()
```

Fully qualified calls such as

```kotlin
val der = at.asitplus.awesn1.encoding.encodeToDer(myValue)
```

also work, but that is not the main migration pattern.

## Final guidance

If you only use built-ins, the migration is mostly:

- import cleanup for ASN.1
- awareness that algorithm families are no longer closed

If you extend Signum, this branch is a major improvement rather than just a migration burden:

- you can define your own algorithm instances
- you can register them centrally
- you can attach JOSE, COSE, X.509, and platform mappings explicitly

That is the intended design now. Code that still assumes a fixed enum-style universe should be updated to match it.
