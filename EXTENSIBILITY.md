# Extensibility

Signum is designed to let external libraries extend its functionality, adding new algorithms and implementations that seamlessly integrate into it.
This document describes the process for library developers.

At the core of extensibility is the `ServiceLoader` gadget. It is used like this:
```kotlin
ServiceLoader.register<ServiceInterfaceType>(ObjectImplementingThatServiceInterfaceType)
```

This needs to be done once before your implementations are available to Signum.
(We hope to replace it with a more intuitive way to register feature providers in the future.)

The rest of this document describes the different kinds of services you can register providers for.

## Message Digests & Message Authentication Codes

Implement `DigestProvider` and `DigestOperationProvider`.
Your digest identifier should implement `Digest`.
`DigestProvider` should implement `getDigest` to map a `X509AlgorithmIdentifier` to your digest identifier class.
`DigestOperationProvider` should implement the actual digest operation as `doDigest`.

Implement `MessageAuthenticationCodeProvider`and `MessageAuthenticationCodeOperationProvider`.
Your MAC identifier should implement `MessageAuthenticationCode`.
`MessageAuthenticationCodeProvider` should implement `getMAC` to map an `X509AlgorithmIdentifier` to your MAC identifier class.
`MessageAuthenticationCodeOperationProvider` should implement the actual MAC operation as `doMAC`.

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
The corresponding encoding operations should be handled by the `asn1Representation` member override in your classes.

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
  override suspend fun makeEphemeralSigner(configuration: EphemeralSignerConfiguration): Signer.WithExportableKey? {
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