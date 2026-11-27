# Extensibility

Signum is designed to let external libraries extend its functionality, adding new algorithms and implementations that seamlessly integrate into it.
This document describes the process for library developers.

## Registration and DER configuration

Extensions should expose one `install()` function that registers providers, any optional wire
serializers, and semantic attribute providers. Applications call it during startup before using those types.

Register core and platform providers through `ServiceLoader.register`.
If a provider needs additional wire serializers on `Signum.Der`, it can also contribute them during registration:

```kotlin
ServiceLoader.register<Asn1PublicKeyFormatProvider>(FoobarKeyFormatProvider)
ServiceLoader.register<JavaKeyStoreOperationsProvider>(FoobarKeystoreProvider)
Signum.registerAsn1Serializers(asn1Serializers)
```

Providers registered later are tried first. Install Supreme before registering overrides for its operation providers.

Signum uses one application-wide `Signum.Der` instance. Public signing, verification, platform conversion,
and ASN.1 representation helpers use it automatically. Nested ASN.1 codecs use the same instance.
The selected awesn1 template supplies its wire serializers.
Core provider installation is lazy and idempotent; it is also available explicitly as `Signum.installIndispensable()`.

### DER templates

On first access, Signum creates its own DER instance from a configuration template. By default, the
template is awesn1's finalized `DER`: Signum copies its settings and serializers, then applies its
registered extension serializers. `Signum.Der !== DER`, even when the instances produce the same bytes
and enforce the same limits.

awesn1 may already have encoded or decoded values before Signum starts. Its default instance remains
a valid template after the `DefaultDer` registry has sealed; Signum does not register anything into
that registry. For example:

```kotlin
val awesn1Der = DER
val bytes = awesn1Der.encodeToByteArray(EcdsaSigValue(Asn1Integer.ONE, Asn1Integer(2)))

val signature = EcdsaSignature.fromRawSignatureValue(bytes)
check(Signum.Der !== awesn1Der)
check(signature.asn1.toRepresentation().rawBytes.contentEquals(bytes))
```

Optionally select a custom configuration **before** installing extensions:

```kotlin
Signum.setDer(DER {
    maxInputLength = 1_000_000
    maxNestingDepth = 64
})
Signum.installSupreme() // when using Supreme; install its defaults before overrides
FoobarExtension.install()

val bytes = publicKey.asn1.toDer()
val key = PublicKey.fromAsn1(bytes)
```

Signum copies all four template settings (`encodeDefaults`, `explicitNulls`, `maxInputLength`, and
`maxNestingDepth`) and its serializers. `Signum.Der` is distinct from a custom template too. Selecting
a custom template does not initialize awesn1's default `DER` or seal its `DefaultDer` registry.
Signum helpers use the single finalized `Signum.Der`; they do not accept a separate configuration for each call.

### Startup order and serializer precedence

The two registries have independent lifecycles:

- Configure awesn1's `DefaultDer` settings and register its serializers before the first access to
  awesn1's `DER`.
- Optionally call `Signum.setDer(...)` once, then install Signum extensions and contribute serializers
  before the first access to `Signum.Der`. Earlier use of awesn1's `DER` does not close this window.
- Repeated accesses return the same Signum instance. Late template selection or Signum serializer
  contribution throws. Signum's contributions do not modify the awesn1 instance or registry.

Perform startup configuration on one thread. Calling a Signum encoding or decoding helper can access
`Signum.Der`, so complete Signum serializer registration before using those helpers.
Contribute wire serializers before first access to `Signum.Der`. Provider-only registration remains mutable,
including attribute names, aliases, and text construction. Later providers take precedence; previous
lookups do not freeze registration.

Serializer precedence is the selected template, then contributions in registration order;
later contributions replace earlier registrations for the same type.
Register native open-polymorphic payload serializers (such as custom `otherName` types) through
`Signum.registerAsn1Serializers` alongside your provider installation.

## Representations and Encoding

Semantic types implement `WithSourceRepresentation`. Each instance supplies a backing
`SourceRepresentationStorage`, which holds its original decoded model when one exists. The model's
concrete type identifies its representation; there is no separate format-key enum or source pair.
`sourceFormat` exposes the retained model's type name, or `<no source>` for a constructed value.

Use `SignumEncodingHelpers.decodeFrom` / `encodeTo` for explicit conversions, or `decodeWith` /
`encodeWith` to dispatch through providers. The ASN.1 wrappers expose `.asn1.toRepresentation()`,
`.asn1.toTlv()`, `.asn1.toDer()`, and companion `fromAsn1(...)` overloads for models, TLVs, DER, and streams.
Signum's ASN.1 and PEM helpers use `Signum.Der`. Its `maxInputLength` constrains DER byte input,
including nested byte decoding; it does not constrain encoded output or re-check the byte size of an
already-parsed TLV element.

Decoded values retain their source for round-trip encoding. Encoding to another format leaves that source
unchanged. Programmatically constructed values have empty storage, even after encoding; getters and
serializers do not cache generated models. Keep storage out of semantic `equals` and `hashCode`.
Return fresh instances from decoders. Reusing an instance for a different source model of the same type
is rejected by the decoding helper to protect its retained representation.

Public constructors take semantic values. `AttributeTypeAndValueProvider` supplies text constructors
and OID/name lookup. `AttributeTypeAndValue.fromString(oid, text)` constructs semantic attributes without
selecting an encoding. ASN.1-specific companion factories, such as `AttributeTypeAndValue(oid, element)`,
decode through providers and retain the supplied wire model.

Keep format-specific tags on serializable wire models and select their serializers explicitly at codec
boundaries. Semantic classes require no contextual ASN.1 registration. C509 is not implemented yet.

## Message Digests & Message Authentication Codes

Implement `Asn1DigestAlgorithmProvider` and `DigestOperationProvider`.
Your digest identifier should implement `Digest`.
`Asn1DigestAlgorithmProvider` should implement `decodeFromAsn1` to map an `X509AlgorithmIdentifier` to your digest identifier class, and `encodeToAsn1` for the reverse conversion.
`DigestOperationProvider` should implement the actual digest operation as `doDigest`.

Implement `Asn1MACAlgorithmProvider` and `MessageAuthenticationCodeOperationProvider`.
Your MAC identifier should implement `MessageAuthenticationCode`.
`Asn1MACAlgorithmProvider` should implement `decodeFromAsn1` to map an `X509AlgorithmIdentifier` to your MAC identifier class, and `encodeToAsn1` for the reverse conversion.
`MessageAuthenticationCodeOperationProvider` should implement the actual MAC operation as `doMAC`.

Digest and MAC identifiers convert through their ASN.1 providers. Use `.asn1.toDer()` and
`fromAsn1(...)`; no contextual serializer registration is needed for the semantic classes.

## Key Derivation Functions

Implement `KDFOperationProvider`.
Your KDF identifier should implement `KDF`.
`KDFOperationProvider` should implement the actual KDF operation as `deriveKey`.

## Encryption and key agreement

Implement `SymmetricEncryptionAlgorithm` and supply `requiredNonceSize` and `authenticationTagSize`
when applicable. For an encrypt-then-MAC construction, implement `SymmetricEncryptionAlgorithmEncryptThenMac`
to supply the inner cipher, MAC, preferred MAC key length, and transformations. The standard
`SealedBox` factories use this metadata to check nonce and tag lengths. `isBlockCipher` and
`isStreamCipher` report independent classifications. An external `SymmetricKey` can keep its key material opaque.

External implementations of `SymmetricEncryptionAlgorithm`, `AsymmetricEncryptionAlgorithm`, and
`KeyAgreementPrivateValue` supply their own operations. The built-in operation entry points throw
`UnsupportedCryptoException` for unsupported implementations. An agreement public value that also
implements `PublicKey` can use its registered public-key format provider for SPKI encoding.

## Signatures

For data formats, implement `Asn1SignatureAlgorithmProvider`, `SignatureFormatProvider`, `Asn1PublicKeyFormatProvider`, and `Asn1PrivateKeyFormatProvider`.
Your signature algorithm identifier should implement `SignatureAlgorithm`.
Your signature format class should implement `Signature`.
Your public key class should implement `PublicKey`.
Your private key class should implement `PrivateKey`, and likely `PrivateKey.WithPublicKey`.

Use `ECCurve` for named curve parameters and `ECPoint` for a curve-specific point representation.
Implement `ShortWeierstrassCurve` to use `ShortWeierstrassCurve.Point` with an external curve over a
prime field. External curves can use their own key formats and signing through the existing providers.
Register an `EcdsaPublicKeyDerivationProvider` to construct `EcdsaPrivateKey.WithPublicKey` on an
external curve. Signum uses the derived point to validate supplied public keys.
Signum's built-in EC arithmetic and Supreme's built-in operations support P-256, P-384, and P-521.
`ECCurveSerializer` retains the existing wire names for those curves.

`Asn1SignatureAlgorithmProvider` should implement `decodeFromAsn1` to map an `X509AlgorithmIdentifier` to your algorithm identifier.
`SignatureFormatProvider` should implement `parseSignature` to parse `X509SignatureValue`s given an algorithm identifier.
`Asn1PublicKeyFormatProvider` should implement `decodeFromAsn1` and, if desired `decodeFromDidKey`.
`Asn1PrivateKeyFormatProvider` should implement `decodeFromAsn1`.
Each of these four format providers also exposes `encodeToAsn1` for the corresponding Signum type.
Return `null` for values your provider does not support. The encoding methods default to `null`, so providers that only decode remain valid.

The `.asn1.toRepresentation()` extensions reuse a matching retained source, or ask the registered
providers to construct the wire model. Producing another format leaves the original source unchanged.
Your provider should construct the model directly rather than recursively calling the same base conversion.

### Explicit wire serializers and installation

Register the provider; semantic Signum classes need no contextual ASN.1 serializers:

```kotlin
fun install() {
    ServiceLoader.register<Asn1SignatureAlgorithmProvider>(FoobarProvider)
    ServiceLoader.register<SignatureFormatProvider>(FoobarProvider)
    ServiceLoader.register<Asn1PublicKeyFormatProvider>(FoobarProvider)
    ServiceLoader.register<Asn1PrivateKeyFormatProvider>(FoobarProvider)
}

val der = publicKey.asn1.toDer()
val decoded = PublicKey.fromAsn1(der)
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

### Android KeyStore

Implement `AndroidKeyStoreOperationsProvider`. `initKeyGenSpec` receives the resolved configuration and returns the JCA algorithm and a builder for the supplied alias. Return `null` to decline a configuration. The default `generateKeyPair` applies Supreme's certificate, attestation, authentication, and backing policy to the builder.

```kotlin
private class ExternalTeeConfiguration : DSL.Data() {
    var curveName = "secp256r1"
}
private val AndroidSigningKeyConfiguration.externalTee
    get() = _algSpecific.option("EXT_TEST_TEE_ECDSA", ::ExternalTeeConfiguration)

private object ExternalTeeProvider : AndroidKeyStoreOperationsProvider {
    @OptIn(SignumInternals::class)
    override fun supportsStrongBox(algorithm: String) = false

    override fun initKeyGenSpec(
        alias: String, config: AndroidSigningKeyConfiguration,
    ): Pair<String, KeyGenParameterSpec.Builder>? {
        val resolved = config.externalTee.v ?: return null
        val jcaKeyAlgorithm = KeyProperties.KEY_ALGORITHM_EC
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec(resolved.curveName))
            .setDigests(KeyProperties.DIGEST_SHA256)
        return jcaKeyAlgorithm to builder
    }

    override fun getAndroidKeystoreSigner(
        jcaPrivateKey: PrivateKey, alias: String, keyInfo: KeyInfo,
        config: AndroidSignerConfiguration, publicKey: PublicKey,
        attestation: AndroidKeystoreAttestation?,
    ): AndroidKeystoreSigner? {
        if (!alias.startsWith("external-tee-") || publicKey !is EcdsaPublicKey) return null
        return object : AndroidKeystoreSigner(
            jcaPrivateKey, alias, keyInfo, "SHA256withECDSA", config, attestation
        ) {
            override val publicKey = publicKey
            override val signatureAlgorithm = EcdsaAlgorithm(Digest.SHA256, publicKey.curve)
            override fun parseSignatureFromJca(bytes: ByteArray) =
                signatureAlgorithm.parseJCASignature(bytes)
        }
    }
}
```

After `Signum.installSupreme()`, register your provider with `ServiceLoader.register<AndroidKeyStoreOperationsProvider>(...)`. Key generation tries the most recently registered provider first. A `null` result lets the next provider try. Generation exceptions propagate to the caller. The alias lookup calls `getAndroidKeystoreSigner` with native metadata and the attestation chain when available.

`AndroidKeystoreSigner` supplies the authenticated signing flow. Pass the JCA signature name accepted by Android Keystore and map native signature bytes with `parseJCASignature`. This example uses a P-256 test key and an alias prefix to select the fixture. An extension can select its signer using its own public-key type.

Override `supportsStrongBox(algorithm)` to return `false` for a TEE-only algorithm. With `strongBox = PREFERRED`, Supreme skips StrongBox for that algorithm. `REQUIRED` fails before generation. Set `hardware { backing = REQUIRED }` to require hardware backing.

### iOS Keychain

Implement `IosKeychainOperationsProvider.getOperationsBundle` to supply the native key type, size,
purposes, and algorithm metadata. Supreme adds the alias tags and access control, generates and stores
the keys, and performs the configured App Attest binding. Return `null` for unsupported configurations.

Implement `makeIosSigner` to recognize the stored algorithm metadata and construct an `IosSigner`
subclass. Its protected constructor and `secKeyType` hook require `@OptIn(SignumInternals::class)`.
Supreme uses that key type when loading the private key. Supply the signature algorithm and implement
`bytesToSignature` using the existing `IosMappingProvider` signature parser.

The external test adapter uses ECDSA with SHA-224, which Apple's Security framework supports and
Supreme's built-in iOS ECDSA signer does not select.

```kotlin
@OptIn(SignumInternals::class, ExperimentalForeignApi::class)
private class ExternalSha224Signer(
    alias: String,
    override val publicKey: EcdsaPublicKey,
    metadata: IosKeyMetadata,
    config: IosSignerConfiguration,
) : IosSigner(alias, metadata, config) {
    override val secKeyType get() = kSecAttrKeyTypeEC
    override val signatureAlgorithm = ExternalSha224
    override fun bytesToSignature(sigBytes: ByteArray) =
        signatureAlgorithm.parseSecKeySignature(sigBytes)
}
```

Here `ExternalSha224` is the adapter's `SignatureAlgorithm`. Its `IosMappingProvider` maps it to
`kSecKeyAlgorithmECDSASignatureMessageX962SHA224` and parses the resulting ECDSA signature bytes.
The superclass handles private-key retrieval, authentication prompts and reuse, signing permission,
native signing, and unlock errors. Register the operations and mapping providers after
`Signum.installSupreme()` and use the existing `IosKeychainProvider` alias methods.
The [external iOS testcase](https://github.com/a-sit-plus/signum/blob/feature/providerReuse/extensibility-test/src/iosTest/kotlin/at/asitplus/signum/supreme/os/ExternalIosAliasTest.kt)
exercises creation, fresh signer lookup, signing, verification, and deletion.

### JVM and Android JKS

Implement `JavaKeyStoreOperationsProvider.createKeyPair` and `getJKSSigner`. Return `null` for configurations or stored key types your adapter does not support so Supreme's built-in ECDSA and RSA handlers remain available. Map the JCA public key, signature algorithm, and signature bytes through `JcaMappingProvider`; JKS obtains its public key from the stored certificate.

### Shared DSL option

Define one DSL extension property on `PlatformSigningKeyConfigurationBase<*>._algSpecific` for your algorithm (see [DSL Extensibility]) and use it across the platform providers. Add a signer-option extension only when the signer needs additional configuration. This lets common code select the same algorithm on each platform.

## Certificate extensions and names

A custom extension implements `CertificateExtension`, including its OID, critical flag, and source storage.
A `CertificateExtensionProvider` converts between that semantic type and `X509CertificateExtension`.
Register it with `ServiceLoader.register<CertificateExtensionProvider>(MyExtensionProvider)`; return `null` for unsupported types or OIDs.
No separate extension registry or contextual semantic serializer is required.

`GeneralNameFormatProvider` follows the same pattern for `GeneralName` and `X509GeneralName`.

X.500 text attributes use `AttributeTypeAndValueProvider` for semantic construction and DN naming:

```kotlin
object MyAttributeProvider : AttributeTypeAndValueProvider {
    override fun decoderFor(oid: ObjectIdentifier): ((String) -> AttributeTypeAndValue)? =
        if (oid == MyAttribute.oid) ::MyAttribute else null

    override fun oidForName(name: String): ObjectIdentifier? =
        MyAttribute.oid.takeIf { name == "MYATTR" || name == "MYALIAS" }

    override fun nameForOid(oid: ObjectIdentifier): String? =
        "MYATTR".takeIf { oid == MyAttribute.oid }
}

ServiceLoader.register<AttributeTypeAndValueProvider>(MyAttributeProvider)
```

`AttributeTypeAndValue.oidForName` normalizes input names to uppercase; `nameForOid` resolves a canonical
name for RFC 2253 output. `decoderFor` returns a constructor for a supported OID, or `null`. The constructor
is invoked inside provider dispatch, so failures allow lower-priority providers to try the same input.
The ASN.1 text adapter uses this same service; each provider can decline an OID before its payload is read.

The core provider supplies standard names, aliases, and generic text attributes without a descriptor
registry or initializing `Signum.Der` for text construction. Provider-only registration also works after earlier name lookups or DER use.
Unknown dotted OIDs with supplied text become generic `TextAttributeTypeAndValue` values, with empty
source storage. RFC 4514 `#` hex values remain explicitly encoded ASN.1 and go through ASN.1 decoding.

Providers return `null` for unsupported inputs and throw when decoding fails. Either outcome lets the
loader try the next provider; the first successful result completes selection. Only after all providers
fail does decoding produce an unknown value extending `ServiceLoader.UnknownShim`, retaining the source
representation and aggregated provider failures. This applies to malformed recognized payloads as well
as unsupported discriminators. A custom provider can therefore decode inputs rejected by the built-in
parser, using the same dispatch mechanism.

To retry a previously unknown value after adding a provider, decode its retained source representation.

The core name types have no `isValid` member. RDN construction checks only structure, so names and
certificates can retain uninterpreted attributes. Basic semantic constructor checks remain in place;
certificate-path validation belongs to separate validators.

Encoding back to the source format preserves its representation, including invalid payloads. Conversion
to another format requires a supporting provider. Certificate serial-number parsing remains lenient,
while programmatic serial-number construction remains strict.

## App Attest client data

`IosHomebrewAttestation.ClientData` encodes RSA keys and EC keys on the built-in curves in the
original JSON form. For other keys it emits an integer `version` of `2` and uses the registered
public-key format provider to encode and decode a base64url DER SubjectPublicKeyInfo. Install that
provider before preparing or parsing client data. App Attest binds the exact `clientDataJSON` bytes
to the App Attest key. Use a separate proof of possession for the public key in the client data.

## Platform type conversions

Sometimes, low-level interfacing with the platform types is required.
Signum Indispensable offers support for this through conversion methods.
These conversion methods are also themselves extensible by your algorithms.

Additionally, some of Signum Supreme's platform providers (JKS, Android KeyStore, iOS Keychain) also use them.

On Android & JVM, implement `JcaMappingProvider`:

- `getJCAMessageDigestInstance` to map Signum `Digest` -> JCA `MessageDigest`
- `getJCASignatureInstance` and `getJCASignatureInstancePreHashed` to map Signum `SignatureAlgorithm` -> JCA `Signature`
  - `parseJCASignatureBytes` and `getJCASignatureBytes` to map Signum `Signature` <-> output of this JCA `Signature` instance
- `publicKeyToJcaPublicKey` and `jcaPublicKeyToPublicKey` to map Signum `PublicKey` <-> JCA `PublicKey`
- `privateKeyToJcaPrivateKey` and `jcaPrivateKeyToPrivateKey` to map Signum `PrivateKey` <-> JCA `PrivateKey`
- `curveForJcaName` and `jcaNameForCurve` to implement `ECCurve.byJcaName` and `ECCurve.jcaName`

On iOS, implement `IosMappingProvider`:

- `signatureAlgorithmToSecKeyAlgorithm` and `signatureAlgorithmToSecKeyAlgorithmPreHashed` to map Signum `SignatureAlgorithm` -> Security `SecKeyAlgorithm`
  - `parseSignatureBytes` and `getSignatureBytes` to map Signum `Signature` <-> Security `SecKeyCreateSignature`/`SecKeyVerifySignature` with the algorithm
- `secKeyToPublicKey` and `publicKeyToSecKey` to map Signum `PublicKey` <-> Security `SecKeyRef`
- `secKeyToPrivateKey` and `privateKeyToSecKey` to map Signum `PrivateKey` <-> Security `SecKeyRef`


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
