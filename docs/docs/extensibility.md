# Extensibility

Signum is designed to let external libraries extend its functionality, adding new algorithms and implementations that seamlessly integrate into it.
This document describes the process for library developers.

## Registration and DER configuration

All extensibility registration and registry lookups go through `Signum`. Register a provider and its
concrete ASN.1 serializers together:

```kotlin
Signum.register(FoobarProvider, serializers = asn1Serializers)
```

This registers every Indispensable provider interface implemented by the object, including the current
platform's JCA or iOS mapping interface. Core defaults are installed before the provider, and later
providers are tried first. Install Supreme before registering overrides for its operation providers.
For module-specific service interfaces, use explicit typed registration:

```kotlin
Signum.registerProvider<JavaKeyStoreOperationsProvider>(FoobarKeystoreProvider)
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

Optionally select a custom configuration **before** installing extensions:

```kotlin
Signum.setDer(DER {
    maxInputLength = 1_000_000
    maxNestingDepth = 64
})
Signum.installSupreme() // when using Supreme; install its defaults before overrides
FoobarExtension.install()
Signum.installPkix() // when using the typed PKIX module

val bytes = Signum.Der.encodeToByteArray(foobarPublicKey)
val key = Signum.Der.decodeFromByteArray<FoobarPublicKey>(bytes)
```

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
These interfaces replace `DerEncodable` and `DerDecodable` and do not prescribe an ASN.1 representation.
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

Implement `DigestProvider` and `DigestOperationProvider`.
Your digest identifier should implement `Digest`.
`DigestProvider` should implement `getDigest` to map an `X509AlgorithmIdentifier` to your digest identifier class, and `encodeToAsn1` for the reverse conversion.
`DigestOperationProvider` should implement the actual digest operation as `doDigest`.

Implement `MessageAuthenticationCodeProvider` and `MessageAuthenticationCodeOperationProvider`.
Your MAC identifier should implement `MessageAuthenticationCode`.
`MessageAuthenticationCodeProvider` should implement `getMAC` to map an `X509AlgorithmIdentifier` to your MAC identifier class, and `encodeToAsn1` for the reverse conversion.
`MessageAuthenticationCodeOperationProvider` should implement the actual MAC operation as `doMAC`.

Digest and MAC identifiers convert through their ASN.1 providers. Use `.asn1.toDer()` and
`fromAsn1(...)`; no contextual serializer registration is needed for the semantic classes.

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

`SignatureAlgorithmsProvider` should implement `decodeFromAsn1` to map an `X509AlgorithmIdentifier` to your algorithm identifier.
`SignatureFormatProvider` should implement `parseCryptoSignature` to parse `X509SignatureValue`s given an algorithm identifier.
`PublicKeyFormatProvider` should implement `decodeFromAsn1` and, if desired `decodeFromDidKey`.
`PrivateKeyFormatProvider` should implement `decodeFromAsn1`.
Each of these four format providers also exposes `encodeToAsn1` for the corresponding Signum type.
Return `null` for values your provider does not support. The encoding methods default to `null`, so providers that only decode remain valid.

The `.asn1.toRepresentation()` extensions reuse a matching retained source, or ask the registered
providers to construct the wire model. Producing another format leaves the original source unchanged.
Your provider should construct the model directly rather than recursively calling the same base conversion.

### Explicit wire serializers and installation

Register the provider; semantic Signum classes need no contextual ASN.1 serializers:

```kotlin
fun install() {
    Signum.register(FoobarProvider)
}

val der = publicKey.asn1.toDer()
val decoded = CryptoPublicKey.fromAsn1(der)
```

Within a provider, use a serializable wire type and its explicit serializer:

```kotlin
val wire = Signum.Der.decodeFromByteArray(MyWire.serializer(), bytes)
val bytes = Signum.Der.encodeToByteArray(MyWire.serializer(), wire)
```

Keep wire fields in wire types as well: for example, use `X509GeneralName` and convert it to/from
`GeneralName` at the provider boundary. The semantic class stays independent of the encoding.
Use `Signum.Der` for nested serialization so application configuration is honored.

A generic signature's BIT STRING does not identify its algorithm. Decode as `AbstractSignature`,
then supply an algorithm using `withSignatureAlgorithm`.
Optional open-polymorphic registrations for application-defined wire types can still be contributed
through `Signum.registerAsn1Serializers` before first DER use.

### Signing operations

For actual operations, implement the following:

- `SignatureVerifierProvider` to provide signature verifiers for your algorithm
    - If you depend on _Supreme_, it provides platform verifier templates that you can use.
      Refer to `SupremeJVMVerifierProvider` and `SupremeCCVerifierProvider` for the template code to adapt.
      Using these templates also requires you to implement the platform conversion providers listed further down.
- `InMemoryKeysProvider` to provide in-memory signing operations:
    - Override `makeEphemeralSigner` to provide ephemeral key creation (via `Signer.Ephemeral`). 
        - You will need to provide a DSL extension property for an `EphemeralSignerConfiguration._algSpecific` option. See [DSL Extensibility].
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
    - Additionally, in common code, define your DSL extension properties (see [DSL Extensibility]):
        - Add an `PlatformSigningKeyConfigurationBase<*>._algSpecific` option to select key creation using your algorithm.
        - Optionally, if your (platform) signers need additional configuration, provide a DSL extension property on `SignerConfiguration` and/or on `PlatformSignerConfigurationBase`.
        - This extension property should be used by all of your provider integrations.
          This enables seamless platform-specific key creation and usage from common code.

## Certificate extensions and names

A custom extension implements `CertificateExtension`, including its OID, critical flag, and source storage.
A `CertificateExtensionProvider` converts between that semantic type and `X509CertificateExtension`.
Register it with `Signum.register(MyExtensionProvider)`; return `null` for unsupported types or OIDs.
No separate extension registry or contextual semantic serializer is required.

`GeneralNameFormatProvider` follows the same pattern for `GeneralName` and `X509GeneralName`.
The open `OtherName` family and policy qualifiers retain uninterpreted payloads in their source
representation. Applications may interpret raw payloads manually or provide explicit conversions;
open-polymorphic wire registration is optional.

For an X.500 text attribute, register its `AttributeTypeAndValue.Descriptor` before the first attribute
lookup, then optionally add aliases:

```kotlin
Signum.register(MyAttribute)
Signum.registerAttributeAlias("MYATTR", MyAttribute.oid)
```

Descriptors contain semantic metadata and string construction. They do not register serializers or
initialize `Signum.Der`. `Signum.attributeOidFor`, `attributeNameFor`, and `attributeDescriptorForName`
provide name resolution.

Unknown and malformed extension bodies become `CertificateExtension.Unknown`, retaining the original
OID, critical flag, wire payload, and provider lookup failures. Encoding back to the source format
preserves that representation. Conversion to another format requires a supporting provider.

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

Most generic structures in Signum are configured using DSL notation:
```kotlin
Signer.Ephemeral { ec { curve = ECCurve.SECP_384_R_1 } }
```

This is realized using our DSL data structures.
(For those interested, refer to `ConfigurationDSL.kt`.)

For extensibility purposes, the DSL operates using extension properties.
Some extension points ask you to define your own algorithm-specific options.
Here is how you do this:

- To **define a new mutually-exclusive option**: define an extension property on the DSL structure using the `option(...)` member of the specified generic, like this: 
  ```kotlin
  val EphemeralSignerConfiguration.foobar get() =
      _algSpecific.option("at.mypackage.mylibrary.foobar", ::FoobarAlgSpecificConfiguration)
  ```
  The string key needs to differ from all other possible options for this generic, or undefined behavior may result.
  Choose a string that is sufficiently unique.
  `FoobarAlgSpecificConfiguration` should extend `DSL.Data` (or an indicator subclass where specified by the generic holder, such as `EphemeralSignerConfiguration.AlgorithmSpecific` here):
  ```kotlin
  class FoobarAlgSpecificConfiguration : EphemeralSignerConfiguration.AlgorithmSpecific() {
    var key: Int = 42
  }
  ``` 
  This then allows consumers to configure your algorithm as:
  ```kotlin
  Signer.Ephemeral { foobar { key = 21 } }
  ``` 
  In your provider implementation (in this case `InMemoryKeysProvider::makeEphemeralSigner`), you can then check if your algorithm was selected:
  ```kotlin
  override suspend fun makeEphemeralSigner(config: EphemeralSignerConfiguration): Signer.WithExportableKey? {
    val algSpecificConfiguration = configuration.foobar.v
    if (algSpecificConfiguration == null) return null
    /* ... create an ephemeral key as configured, then wrap it in a signer */
  }
  ```
- To **integrate a DSL property** that doesn't interact with existing properties: define an extension property on the DSL structure using its `childOrDefault`, `childOrNull`, etc, methods, like this:
  ```kotlin
  val SignerConfiguration.foobar get() =
    childOrDefault("at.mypackage.mylibrary.foobar", ::FoobarSignerConfiguration)
  ```
  The string key needs to differ from all other DSL properties on this DSL type, or undefined behavior may result.
  Choose a string that is sufficiently unique.
  `FoobarSignerConfiguration` should extend `DSL.Data`.
  ```kotlin
  class FoobarSignerConfiguration : DSL.Data() {
    var extraSalt: ByteArray = byteArrayOf()
    class SugarStirringConfiguration : DSL.Data() {
      var stirLeft: Boolean = false
    }
  }
  val FoobarSignerConfiguration.sugar get() =
    childOrDefault("sugar", FoobarSignerConfiguration::SugarStirringConfiguration)
  ```
  This also demonstrates how you can nest DSL data structures inside each other.
  As an aside: There is no specific reason, beyond convention why `sugar` needs to be an extension property here.
  You could place the same property, with or without a backing field, inside the DSL class itself.
  Note that the classes returned from `childOrNull` etc. are only accessors into the underlying generic storage defined on `DSL.Data` itself.
  Only generic accessors (the objects you call `.option` on) hold their own storage and need backing fields.
  Refer to `ConfigurationDSL.kt` and the `DSLInheritanceDemonstration`/`DSLVarianceDemonstration` test sources if you wish to customize your DSL data structures fully.
  
  This particular nested structure can then be configured as such:
  ```kotlin
  SigningProvider.Platform{}.getSignerForKey("my_alias") {
    foobar {
      extraSalt = byteArrayOf(0x42)
      sugar {
        stirLeft = true
      }
    }
  }
  ```
  You can retrieve the configured structure using `.v` on the accessor, as demonstrated earlier:
  ```kotlin
  override fun getJKSSigner(/* ... */ config: JKSSignerConfiguration, /* ... */) : JKSSigner? {
    if (certificate.publicKey !is FoobarPublicKey) return null
    val algSpecificConfiguration = config.foobar.v
    val sugar = algSpecificConfiguration.sugar.v
    /* ... create a JKS signer appropriately selecting the SignatureAlgorithm to use based on public key and configuration */
  }
  ```
