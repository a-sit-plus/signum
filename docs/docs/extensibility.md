# Extensibility

Signum is designed to let external libraries extend its functionality, adding new algorithms and implementations that seamlessly integrate into it.
This document describes the process for library developers.

## Registration and DER configuration

All extensibility registration and registry lookups go through `Signum`. Register providers and their
concrete ASN.1 serializers during startup, before resolving DER. This function installs the examples
introduced below in the required order:

```kotlin
--8<-- "extensibility-test/src/jvmTest/kotlin/at/asitplus/signum/examples/ExtensibilityExamples.kt:extension-bootstrap"
```

1. Select the DER settings before contributing serializers.
2. Register the educational digest provider together with its concrete serializer.
3. Register the custom certificate-extension descriptor and its concrete serializer together.
4. Resolve DER only after all serializer contributions are installed.

This registers every Indispensable provider interface implemented by the object, including the current
platform's JCA or iOS mapping interface. Core defaults are installed before the provider, and later
providers are tried first. Install Supreme before registering overrides for its operation providers.
Use explicit typed registration to override an operation provider. Provider-only registration remains
possible after DER has been resolved:

```kotlin
--8<-- "extensibility-test/src/jvmTest/kotlin/at/asitplus/signum/examples/ExtensibilityExamples.kt:extension-override-provider"
```

The bootstrap installs this override after resolving DER. It takes precedence when the operation is requested:

```kotlin
--8<-- "extensibility-test/src/jvmTest/kotlin/at/asitplus/signum/examples/ExtensibilityExamples.kt:extension-provider-precedence"
```

An extension should expose one `install()` function that registers its providers, contextual serializers,
and any certificate-extension or name descriptors. Applications call it during startup before using those types.

Signum uses one application-wide `Signum.Der` instance. Public signing, verification, platform conversion,
and chain-validation helpers use it automatically for all things serialization. Nested codecs and deferred
semantic decoding use the same instance. The core serializers are included automatically;
`Signum.installPkix()` registers the PKIX descriptors and their serializers.
Module installers are extension functions on `Signum`, defined in their respective modules; core
Indispensable does not depend on Supreme or PKIX. Core provider installation remains lazy and idempotent;
it is also available explicitly as `Signum.installIndispensable()`.

Optionally select a custom configuration **before** installing extensions, as shown in the bootstrap example above.

`setDer` supplies a template: Signum creates a new instance preserving its settings and existing serializers,
then adds its core and registered extension serializers. Omit `setDer` to use awesn1's default `DER` instance;
Signum registers the complete module there before resolving it. First access to `Signum.Der` seals serializer registration.
Call `setDer` at most once, before any serializer contribution. Late selection or serializer contribution throws.
Each descriptor registry seals on its first lookup; combined descriptor/serializer registration requires
both stores to remain open. Provider-only registration retains its existing mutable behavior, allowing
lazy module installation. Centralization does not introduce a single shared freeze point.
Configure and install on one thread during startup; do not access awesn1's default `DER` before bootstrap.
Serializer precedence is core, then the custom template, then contributions in registration order;
later contributions replace earlier registrations for the same type.
Register native open-polymorphic payload serializers (such as custom `otherName` types) through
`Signum.registerAsn1Serializers` alongside your provider installation.

## Representations and Encoding

Semantic types implement `Encodable`; their companions can implement `Decodable<T>` as a typed decoding target.
For Signum semantic types, these replace the old `Asn1Encodable` and `Asn1Decodable` contracts and do not prescribe an ASN.1 representation.
Encoding and decoding use contextual serializers through `Signum.Der`, including awesn1's TLV and kotlinx.io APIs.
Signum's PEM extensions also use `Signum.Der`.

`Encodable.sourceRepresentation` is a nullable `Pair<Encodable.Representation, Any>`: one format key
and the original decoded model. The key implements an open interface; `X509` identifies an ASN.1 source,
and other formats can define their own keys. A decoded value retains only its source, preserving
round-trip accuracy. Programmatically constructed values have `null`, even after encoding;
getters and serializers never store generated models there. Exclude the pair from semantic
`equals` and `hashCode`. Public constructors take semantic values; constructors accepting a retained
source pair should be internal or private. Companion `fromAsn1Representation` functions provide
conversion from matching awesn1 models.

Attribute descriptors provide `fromValue(Asn1Element)` for programmatic OID/value construction,
separately from `fromAsn1Representation` for decoding. The former must leave the source pair null.

Keep format-specific tags and explicit serializers on wire models. Shared semantic types should use
contextual serializers so another format can choose its own representation. `GeneralSubtree` and its
internal `X509GeneralSubtree` illustrate this separation. C509 is not implemented yet.

## Message Digests & Message Authentication Codes

Here is a complete educational checksum provider. Byte sums are not secure hashes! The provider handles
its own algorithm and returns `null` for others, allowing Supreme's providers to handle those.

```kotlin
--8<-- "extensibility-test/src/jvmTest/kotlin/at/asitplus/signum/examples/ExtensibilityExamples.kt:extension-digest"
```

Implement `DigestProvider` and `DigestOperationProvider`.
Your digest identifier should implement `Digest`.
`DigestProvider` should implement `getDigest` to map an `X509AlgorithmIdentifier` to your digest identifier class, and `encodeToAsn1` for the reverse conversion.
`DigestOperationProvider` should implement the actual digest operation as `doDigest`.

Implement `MessageAuthenticationCodeProvider` and `MessageAuthenticationCodeOperationProvider`.
Your MAC identifier should implement `MessageAuthenticationCode`.
`MessageAuthenticationCodeProvider` should implement `getMAC` to map an `X509AlgorithmIdentifier` to your MAC identifier class, and `encodeToAsn1` for the reverse conversion.
`MessageAuthenticationCodeOperationProvider` should implement the actual MAC operation as `doMAC`.

Concrete digest and MAC types also need contextual ASN.1 serializers when consumers encode or decode them
directly. Use the [serializer and installation pattern](#contextual-asn1-serializers-and-installation) below.

## Key Derivation Functions

Implement `KDFProvider` and `KDFOperationProvider`.
Your KDF identifier should implement `KDF`.
`KDFProvider` is currently unused. It may be extended at a later point to provide algorithm identifier resolution.
`KDFOperationProvider` should implement the actual KDF operation as `deriveKey`.

## Signatures

For data formats, implement `SignatureAlgorithmsProvider`, `SignatureFormatProvider`, `PublicKeyFormatProvider`, and `PrivateKeyFormatProvider`.
Your signature algorithm identifier should implement `SignatureAlgorithm`.
Your signature format class should implement `CryptoSignature`.
Your public key class should implement `CryptoPublicKey`.
Your private key class should implement `CryptoPrivateKey`, and likely `CryptoPrivateKey.WithPublicKey`.

`SignatureAlgorithmsProvider` should implement `getAlgorithm` to map an `X509AlgorithmIdentifier` to your algorithm identifier.
`SignatureFormatProvider` should implement `parseCryptoSignature` to parse `X509SignatureValue`s given an algorithm identifier.
`PublicKeyFormatProvider` should implement `decodeFromAsn1` and, if desired `decodeFromDidKey`.
`PrivateKeyFormatProvider` should implement `decodeFromAsn1`.
Each of these four format providers also exposes `encodeToAsn1` for the corresponding Signum type.
Return `null` for values your provider does not support. The encoding methods default to `null`, so providers that only decode remain valid.

The `asn1Representation` extension getters first use `sourceRepresentationFor(X509)`, which returns
the original model only if the source format matches, then ask the registered providers to construct one.
Producing another format's model leaves the source pair unchanged.
Your provider should construct the model directly rather than calling the same base-type getter recursively.

### Contextual ASN.1 serializers and installation

Register a contextual serializer for each concrete type consumers will encode or decode directly.
The base-interface serializers in `signumAsn1Serializers` already use the format providers, but contextual registration for a base interface does not cover its subclasses.
The types themselves do not need `@Serializable` annotations. A class-level generated or custom serializer
takes precedence over contextual registration; avoid fixing an X.509 serializer on a shared semantic type.

Use `contextualAsn1` to bridge your type to an awesn1 model. This example registers the concrete digest
type introduced above; algorithm, key and signature types use the same pattern:

```kotlin
--8<-- "extensibility-test/src/jvmTest/kotlin/at/asitplus/signum/examples/ExtensibilityExamples.kt:extension-serializers"
```

The conversion from the model must return the concrete registered type.
For a generic signature, the BIT STRING does not identify its algorithm: decode as `SignatureValue`, then supply an algorithm using `withSignatureAlgorithm`.
A concrete signature serializer may decode directly if its type provides enough information.

Expose one installation entry point for your extension, alongside its serializer module, then call it during
application startup as shown in the [bootstrap example](#registration-and-der-configuration).

### Signing operations

For actual operations, implement the following:

- `SignatureVerifierProvider` to provide signature verifiers for your algorithm
    - If you depend on _Supreme_, it provides platform verifier templates that you can use.
      Refer to `SupremeJVMVerifierProvider` and `SupremeCCVerifierProvider` for the template code to adapt.
      Using these templates also requires you to implement the platform conversion providers listed further down.
- `InMemoryKeysProvider` to provide in-memory signing operations:
    - Override `makeEphemeralSigner` to provide ephemeral key creation (via `Signer.Ephemeral`). 
        - You will need to provide a DSL extension property for an `EphemeralSignerConfiguration._algSpecific` option. See [DSL Extensibility](#dsl-extensibility).
    - Override `createSignerForKey` to provide in-memory signer creation for existing keys.
        - If you depend on _Supreme_, you can once again reuse its platform class templates.
          See `SupremeJVMInMemoryKeysProvider` and `SupremeIosInMemoryKeysProvider`.
          You will need to implement the platform conversion providers.
- If you depend on _Supreme_, you can also integrate with its platform-specific signing providers.
    - Implement the following classes in platform code:
        - `AndroidKeyStoreOperationsProvider` to support hardware-backed keys (on Android):
            - For key creation, override either `initKeyGenSpec` (preferred), or `generateKeyPair`.
              If you override `generateKeyPair`, you will need to re-implement the security settings, which the default implementation handles for you.
            - Additionally, override `getAndroidKeystoreSigner` to produce the actual signer object.
              Your returned object needs to subclass `AndroidKeystoreSigner`, which already implements security handling.
              Refer to the existing Supreme subclasses for the minimal shim to use. 
        - `IosKeychainOperationsProvider` to support hardware-backed keys (on iOS):
            - For key creation, override either `getOperationsBundle` (preferred) or `makeKeyAttributes`.
              If you override `makeKeyAttributes`, make sure to refer closely to the default implementation to maintain compatibility with the `IosKeychainProvider`.
            - Additionally, override `makeIosSigner` with a minimal shim.
              See the existing Supreme implementation for the shim to use.
        - `JavaKeyStoreOperationsProvider` integration with JKSProvider (on Android+JVM).
            - For key creation, override `createKeyPair`.
            - Additionally, override `getJKSSigner` with a minimal shim.
              See the existing Supreme implementation for the shim to use.
    - Additionally, in common code, define your DSL extension properties (see [DSL Extensibility](#dsl-extensibility)):
        - Add an `PlatformSigningKeyConfigurationBase<*>._algSpecific` option to select key creation using your algorithm.
        - Optionally, if your (platform) signers need additional configuration, provide a DSL extension property on `InMemorySignerConfiguration` and/or on `PlatformSignerConfigurationBase`.
        - This extension property should be used by all of your provider integrations.
          This enables seamless platform-specific key creation and usage from common code.

## Certificate extensions

The custom flag below uses a private experimental OID and a one-byte body, solely to demonstrate registration.
Do not use that wire format or OID as an interoperable certificate extension.

A custom extension implements `CertificateExtension`. Its companion implements
`CertificateExtension.Descriptor<MyExtension>`, which extends `Decodable<MyExtension>`, and provides
its OID and `fromAsn1Representation` returning the concrete type.

```kotlin
--8<-- "extensibility-test/src/jvmTest/kotlin/at/asitplus/signum/examples/ExtensibilityExamples.kt:extension-descriptor"
```

The `Signum.register(ExampleFlag)` call in bootstrap installs both the OID descriptor and the concrete contextual ASN.1 serializer. No separate
serializer module or `@Serializable` annotation is needed. The bridge uses the extension's
`asn1Representation` and the descriptor's conversion from awesn1's `X509CertificateExtension`.

The same pattern applies to `GeneralName.Descriptor<MyName>` (keyed by CHOICE tag) and
`AttributeTypeAndValue.Descriptor<MyAttribute>` (keyed by OID). Register their descriptors through
`Signum.register` and attribute aliases through `Signum.registerAttributeAlias` during bootstrap.

Attribute descriptors also supply a canonical name and `fromString`. Register aliases after their
descriptor and before attribute lookup. `Signum.attributeOidFor`, `attributeNameFor`, and
`attributeDescriptorForName` provide name resolution.

Descriptor lookup uses `Signum.certificateExtensionDescriptorFor`, `generalNameDescriptorFor`, or
`attributeDescriptorFor`. Registration must precede both the first lookup in that registry and first
`Signum.Der` access; rejected combined registrations leave the descriptor and serializer stores unchanged.
PKIX uses these same calls for its built-in types; only types without descriptors, such as `GeneralSubtree`,
need a separate serializer contribution.

A custom native `otherName` payload still needs its open-polymorphic serializer registration through
`Signum.registerAsn1Serializers`. Registering a GeneralName descriptor handles the CHOICE alternative,
not every possible payload OID inside it.

There is no `X509Representable` marker. `CertificateExtension.asn1Representation` is nullable: it reads
`sourceRepresentationFor(X509)`, or constructs the model for an `X509CertificateExtension`. If neither is available,
it returns `null` and DER encoding throws.
If constructing or decoding an extension body requires serialization, use `Signum.Der` so embedded values
use the application's registered serializers and configuration.

Unknown extension OIDs retain their opaque payloads. Decode failures for registered extension OIDs
propagate; do not turn malformed bodies into empty constraints, empty policies, or a generic known extension.

## Platform type conversions

Sometimes, low-level interfacing with the platform types is required.
Signum Indispensable offers support for this through conversion methods.
These conversion methods are also themselves extensible by your algorithms.

Additionally, some of Signum Supreme's platform providers (JKS, Android KeyStore, iOS Keychain) also use them.

On Android & JVM, implement `JcaMappingProvider`:

- `getJCAMessageDigestInstance` to map Signum `Digest` -> JCA `MessageDigest`
- `getJCASignatureInstance` and `getJCASignatureInstancePreHashed` to map Signum `SignatureAlgorithm` -> JCA `Signature`
  - `parseJCASignatureBytes` and `getJCASignatureBytes` to map Signum `CryptoSignature` <-> output of this JCA `Signature` instance
- `cryptoPublicKeyToJcaPublicKey` and `jcaPublicKeyToCryptoPublicKey` to map Signum `CryptoPublicKey` <-> JCA `PublicKey`
- `cryptoPrivateKeyToJcaPrivateKey` and `jcaPrivateKeyToCryptoPrivateKey` to map Signum `CryptoPrivateKey` <-> JCA `PrivateKey`

On iOS, implement `IosMappingProvider`:

- `signatureAlgorithmToSecKeyAlgorithm` and `signatureAlgorithmToSecKeyAlgorithmPreHashed` to map Signum `SignatureAlgorithm` -> Security `SecKeyAlgorithm`
  - `parseSignatureBytes` and `getSignatureBytes` to map Signum `CryptoSignature` <-> Security `SecKeyCreateSignature`/`SecKeyVerifySignature` with the algorithm
- `secKeyToCryptoPublicKey` and `cryptoPublicKeyToSecKey` to map Signum `CryptoPublicKey` <-> Security `SecKeyRef`
- `secKeyToCryptoPrivateKey` and `cryptoPrivateKeyToSecKey` to map Signum `CryptoPrivateKey` <-> Security `SecKeyRef`


## DSL Extensibility

Most generic structures in Signum are configured using DSL notation. This is realized using our DSL data structures.
(For those interested, refer to `ConfigurationDSL.kt`.)
For extensibility purposes, the DSL operates using extension properties.

To **define a new mutually-exclusive option**, define an extension property on the DSL structure using
its `_algSpecific.option(...)` member. Its class must extend the indicator subclass required by the holder,
such as `EphemeralSignerConfiguration.AlgorithmSpecific`.
To **integrate a DSL property** that doesn't interact with existing properties, use `childOrDefault`,
`childOrNull`, etc. The string key needs to differ from all other properties on this DSL type, or undefined
behavior may result. Choose a string that is sufficiently unique.

```kotlin
--8<-- "extensibility-test/src/jvmTest/kotlin/at/asitplus/signum/examples/ExtensibilityExamples.kt:extension-dsl"
```

This also demonstrates how you can nest DSL data structures inside each other.
As an aside: There is no specific reason, beyond convention, why `details` needs to be an extension property here.
You could place the same property, with or without a backing field, inside the DSL class itself.
The classes returned from `childOrNull` etc. are only accessors into the underlying generic storage defined on
`DSL.Data` itself. Only generic accessors (the objects you call `.option` on) hold their own storage and need backing fields.

The provider reads `.v` to check whether its algorithm was selected. Return `null` when it wasn't selected
so another provider can handle the configuration. This provider reuses the test module's one-bit cursory
signature scheme. As the name suggests, that scheme is very insecure! It is only useful for demonstrating
how a custom algorithm plugs into the DSL.

```kotlin
--8<-- "extensibility-test/src/jvmTest/kotlin/at/asitplus/signum/examples/ExtensibilityExamples.kt:extension-dsl-provider"
```

The options are exercised by this configuration and signer creation:

```kotlin
--8<-- "extensibility-test/src/jvmTest/kotlin/at/asitplus/signum/examples/ExtensibilityExamples.kt:extension-dsl-use"
```

Refer to `ConfigurationDSL.kt` and the `DSLInheritanceDemonstration`/`DSLVarianceDemonstration` test sources
if you wish to customize your DSL data structures fully.
