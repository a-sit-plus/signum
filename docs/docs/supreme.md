![Signum Supreme](assets/supreme-dark-large.png#only-light) ![Signum Supreme](assets/supreme-light-large.png#only-dark)

[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus.signum/supreme?label=maven-central)](https://mvnrepository.com/artifact/at.asitplus.signum/supreme)

# **Supreme** KMP Crypto Provider

This [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library provides platform-independent data
types and functionality related to crypto and PKI applications:

* Multiplatform ECDSA and RSA Signer and Verifier &rarr; Check out the included [CMP demo App](https://github.com/a-sit-plus/signum/tree/main/demoapp) to see it in
  action
* Multiplatform AES and ChaCha20-Poly1305
* [Hybrid Public Key Encryption (HPKE)](#hybrid-public-key-encryption)
* Multiplatform HMAC
* Multiplatform RSA Encryption
* Multiplatform KDF/KSF
    * PBKDF2
    * HKDF
    * scrypt
* Biometric Authentication on Android and iOS without Callbacks or Activity Passing** (✨Magic!✨)
* Support Attestation on Android and iOS
* Multiplatform, hardware-backed ECDH key agreement

!!! tip
    **Do check out the full API docs [here](dokka/supreme/index.html)**!

## Using it in your Projects

This library was built for [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html). Currently, it targets
the JVM, Android, and iOS.

Simply declare the desired dependency to get going:

Declare `at.asitplus.signum:supreme:1.0.0` in your commonMain dependencies.

## Key Design Principles
The Supreme KMP crypto provider works differently than the JCA. It uses a `Provider` to manage private key material and create `Signer` instances,
and a `SignatureVerifier`, that is instantiated on a `SignatureAlgorithm`, taking a `CryptoPublicKey` as parameter.
In addition, creating ephemeral keys is a dedicated operation, decoupled from a `Provider`.
The actual implementation of cryptographic functionality is delegated to platform-native implementations, complemented by Kotlin providers.

Symmetric encryption follows a similar paradigm, utilising structured representations of ciphertexts and type-safe APIs.
This prevents misuse and mishaps much more effectively than the JCA.

Moreover, the Supreme KMP crypto provider heavily relies on a type-safe DSL for configuration.
This type-safety goes so far as to expose platform-specific configuration options only in platform-specific sources, even when
the actual calls to some DSL-configurable type reads the same as in common code.

!!! warning
    **Do not ignore the results returned by any operation!**  
    Provider operations, digest/MAC/KDF calculation and key agreement are suspending and return their values directly; failures throw. Verification returns `SignatureVerifier.Success` or throws. Signing returns a `SignatureResult`; access `.signature` to obtain the signature or surface a failure. Symmetric and RSA encryption/decryption, symmetric key import and some secret-key accessors still return `KmmResult`. Handle those results or explicitly use `getOrThrow()`.


## Provider Initialization
Install the Supreme operation providers once at application startup, before registering provider overrides. This is separate from obtaining a provider for persistent key storage:

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-bootstrap"
```

Platform signing providers implement `SigningProvider` to manage signing keys and create signer instances. The JVM uses `JKSProvider`, Android uses `AndroidKeyStoreProvider`, and iOS uses `IosKeychainProvider`. Their initialization differs.

### iOS and Android
On mobile targets (Android and iOS), simply reference the `PlatformSigningProvider` property, and you're good to go!
This provider is backed by the _AndroidKeyStore_ and the _KeyChain_/_Secure Enclave_ and requires no configuration.

### JVM

On the JVM, you need to instantiate the `JKSProvider` back it with a JCA `KeyStore`.
This can either be an already initialized, loaded one, or you can pass a path to a keystore file:

<table>
<tr>
<th>File-Based</th>
<th>with pre-loaded <code>KeyStore</code></th>
</tr>

<tr>
<td>

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-jks-file"
```

</td>
<td>

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-jks-memory"
```

</td>
</tr>
</table>

Usually, passing pre-initialized keystore is enough to cover even custom `KeyStore` implementations depending on
a specific `SecurityProvider`.
In cases where even more flexibility is needed, it is possible to use `withCustomAccessor{}` and pass a custom
KeyStore-accessor, implementing the `JKSAccessor` interface.

In addition, `JKSProvider.Ephemeral()` creates an in-memory provider without persistent backing. `JKSProvider()` selects this mode too.


## Key Management
The provider enables creating, loading, and deleting signing keys.
In addition, it is possible to create a signing key (and a signer) from a `CryptoPrivateKey`.

### Key Generation
A key's properties cannot be modified after its creation.
Fundamental key-generation options, such as key type, are available on all targets and in common code.

The common options include key type and specifics to the key type. 
As EC and RSA keys are the only supported ones, this amounts to the following configuration options:


<table>
<tr>
<th>EC</th>
<th>RSA</th>
</tr>

<tr>
<td>

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-key-ec"
```

</td>
<td>

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-key-rsa"
```

</td>
</tr>
</table>

For EC keys, the digest is optional and if none is set, it defaults to the curve's native digest.
For RSA keys, the set of digests defaults to SHA-256 and the padding defaults to PSS.
It is also possible to override the public exponent, although not all platform respect this override.

#### Key Agreement
If you want to use a hardware-backed key for key agreement, you need to specify the corresponding purpose:

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-key-agreement-purpose"
```

!!! warning inline end
    Key generated using Supreme &leq;0.6.4 don't have the key agreement purpose set and cannot be used for key agreement.
    Regenerate such keys, if you want to use them for key agreement!

On Android, key usage purposes are enforced by hardware, on iOS this enforcement is done in software. On the JVM, no strict checks are enforced
(but this may change in the future). Also note that only EC key agreement is currently supported. Hence, the `keyAgreement` purpose can only be set for EC keys!


#### iOS and Android
Both iOS and Android support attestation, hardware-backed key storage and authentication to use a key.
Since all of this is, at least in part, hardware-dependent, the `PlatformSigningProvider` supports an additional
`hardware` configuration block for key generation.
The following configuration lambdas showcase this feature set. Pass `configureKey` to the corresponding native provider's `createSigningKey(alias, configureKey)` call:

```kotlin
--8<-- "supreme/src/iosTest/kotlin/at/asitplus/signum/examples/IosSupremeExamples.kt:supreme-ios-configuration"
```

```kotlin
--8<-- "supreme/src/androidDeviceTest/kotlin/at/asitplus/signum/examples/AndroidSupremeExamples.kt:supreme-android-configuration"
```

On Android, `hardware.strongBox` independently selects StrongBox using `REQUIRED`, `PREFERRED`, or `DISCOURAGED`. `PREFERRED` falls back when StrongBox is unavailable; `REQUIRED` fails if the requested backing is unavailable. `DISCOURAGED` hardware backing does not guarantee software key storage on Android.

If multiple protections factors are chosen, any one of them can be used to unlock the key.
Biometry could be face unlock or fingerprint unlock, depending on the device and how it is configured.
If no timeout is specified, the key requires authentication on every use.

In case an attestation challenge is specified, an attestation proof is generated alongside the key.
On iOS, this requires an Internet connection! See also [Attestation](#attestation).

!!! warning
    iOS only supports P-256 keys in hardware!
    Yes, this means hardware-backed RSA keys are altogether unsupported on iOS!


#### JVM
The JVM supports no additional configuration options, since it supports none of the above features.

### Key Loading
To load a key, simply call `provider.getSignerForKey(alias) {…}`.
Depending on how the key was created, it may be necessary or just useful to pass additional options.
Most prominently, you may want to display a custom unlock prompt on mobile targets, if the key
is protected by biometry:

```kotlin
--8<-- "supreme/src/iosTest/kotlin/at/asitplus/signum/examples/IosSupremeExamples.kt:supreme-ios-key"
```

```kotlin
--8<-- "supreme/src/androidDeviceTest/kotlin/at/asitplus/signum/examples/AndroidSupremeExamples.kt:supreme-android-key"
```

The native lifecycle examples configure the loading and signing prompts separately. They do not require hardware backing or biometric interaction. The full hardware configuration example is resolved and validated as a DSL configuration; issuing it to the provider requires a suitable device, enrolled protection factors and, on iOS, App Attest entitlements and connectivity.
More often than not, though, you'll want to setup an `unlockPrompt` as part of the signing operation
(see [Signature Creation](#signature-creation)).  
On the JVM (using the `JKSProvider`), another toplevel configuration property is present: `privateKeyPassword`,
which is used to unlock the private key, in case it is password-protected

In addition, EC and RSA-specific configuration options are available, to specify a digest and/or padding.
To configure such algorithm-specific options, invoke the `ec{}` or `rsa{}` block accordingly.

### Key Deletion
Simply call `provider.deleteSigningKey(alias)` to delete a key.
If the operation succeeds, a key was indeed deleted.
If not, it usually means that a non-existent alias was specified.

### Private Key Management
Private key can be loaded from PEM-encoded strings or DER-encoded byte arrays into a `CryptoPrivateKey` object:

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-private-key-decode"
```

These keys currently cannot be imported into platform-native key stores (Android KeyStore/ iOS KeyChain).
Also, while encrypted keys can be parsed, decryption is currently not natively supported.

#### Creating a Signer from a `CryptoPrivateKey`

!!! note inline end 
    Signers can only be created for private keys that have a public key and/or a curve attached. This may not be the case
    when an EC private key was parsed from SEC1 encoding without curve and public key info.

Given a `CryptoPrivateKey.WithPublicKey` object and a `SignatureAlgorithm` object, a signer can be created as follows:

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-private-key-import"
```

This only works if key and signature algorithm are compatible. Otherwise, creating the signer throws.
If you have an EC private key at hand without a public key attached, simply convert it to a `EcdsaPrivateKey.WithPublicKey` as follows:

Attach the known curve using `privateKey.withCurve(ECCurve.SECP_256_R_1)` before creating the signer.

#### Exporting Private Keys

!!! note inline end
    The `exportPrivateKey()` method requires an explicit opt-in for `SecretExposure` to prevent accidental export of private keys

Private keys can be exported (typically to be DER or PEM-encoded) from `Signer.WithExportableKey`, such as ephemeral signers and signers created from imported keys. The returned key is a direct value, and the call is suspending. The following example opts in to `SecretExposure` in its source file:

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-private-key"
```

Platform-native signers do not implement `Signer.WithExportableKey`, so their private key material cannot be exported.


## Signature Creation
Regardless of whether a key was freshly created or a pre-existing key way loaded. The result of either operation
is a `Signer`, which can be used as desired.
To sign, simply pass data to sign.
On iOS and Android, it is possible to configure an `unlockPrompt`, as shown in the [native key lifecycle examples](#key-loading). The basic signing call is the same across platforms:

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-signing"
```

1. Accessing `.signature` surfaces a signing failure; signing itself returns a `SignatureResult`.

## Signature Verification

To verify a signature, obtain a `SignatureVerifier` instance using `verifierFor(publicKey)`, either directly on a
`SignatureAlgorithm`, or on one of the specialized algorithms (`X509SignatureAlgorithm`, `CoseAlgorithm`, ...).
A variety of constants, resembling the well-known JCA names, are also available in `SignatureAlgorithm`'s companion.

As an example, here's how to verify a basic signature using a public key:

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-verification"
```

1. A rejected signature throws. Catch verification failures at the boundary handling untrusted input.

You can also further configure the verifier, for example to specify the `provider` to use on the JVM.
To do this, pass a DSL configuration lambda to `verifierFor`.

There really is not much more to it. This pattern works the same on all platforms.
Details on how to parse cryptographic material can be found in the [section on decoding](indispensable.md) in
the Indispensable module description.


## Ephemeral Keys and Ephemeral Signers
Ephemeral keys and ephemeral signers are not backed by a provider, but are still delegated to platform functionality.
They are just not persisted and work the same across platforms.

To obtain an ephemeral signer, call `Signer.Ephemeral{}` and pass EC or RSA-specific configuration options as you would when creating a key using
the `SigningProvider`.
The signer itself has exportable private key material; a separate ephemeral key object is no longer needed.

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-ephemeral"
```

## Digest Calculation
The provider implements the `digest()` extension on Indispensable's `Digest` interface. The extension is suspending and returns the digest bytes directly.

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-digest"
```
For a list of supported algorithms, check out the [feature matrix](features.md#supported-algorithms).

## HMAC Calculation
The provider implements the suspending `mac()` extension on Indispensable's `MessageAuthenticationCode` interface. It returns MAC bytes directly.

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-hmac"
```

It takes two arguments:

* `key` denotes the MAC key
* `msg` represents the payload to compute a MAC for

For a list of supported algorithms, check out the [feature matrix](features.md#supported-algorithms).

## Symmetric Encryption

Symmetric encryption is implemented in a flexible and type-safe fashion. At the same time, the public interface is also rather lean:

* Reference an algorithm such as `SymmetricEncryptionAlgorithm.ChaCha20Poly1305`.
* Invoke `randomKey()` on it to obtain a `SymmetricKey` object.
* Call `encrypt(data)` on the key and receive a `SealedBox`.

Decryption is the same straight-forward affair:
Simply call `decrypt(key)` on a `SealedBox` to recover the plaintext.

!!! tip inline end
    All data classes (keys, algorithms, ciphertext, MAC, et.) are part of the _indispensable_ module.
    The actual functionality is implemented as extensions in the Supreme KMP crypto provider.

To minimise the potential for error, everything (algorithms, keys, sealed boxes) makes heavy use of generics.
Hence, a sealed box containing an authenticated ciphertext will only ever accept a symmetric key that is usable for AEAD.
Additional runtime checks ensure that no mixups can happen.

### On Type Safety 
The API tries to be as type-safe as possible, e.g., it is impossible to specify a dedicated MAC key (or function) for AES-GCM,
and non-authenticated AES-CBC does not even support passing additional authenticated data to the encryption process.
The same constraints apply to the resulting ciphertexts, making it much harder
to accidentally confuse an authenticated encryption algorithm with a non-authenticated one.
Signum uses the term _characteristics_ for these defining properties of the whole symmetric encryption data model. 

#### Characteristics
Cryptographic algorithms have various obvious properties, such as the underlying cipher
(AES and ChaCha branch off `SymmetricEncryptionAlgorithm` at the root level), `name`, and `keySize`.
The broader _characteristics_ also apply to key and ciphertexts (called `SealedBox` in Signum.)
These are:

* `AuthCapability`: indicating whether it is an authenticated cipher, and if so, how:
    * `Unauthenticated`: Non-authenticated encryption algorithm
    * `Authenticated`: AEAD algorithm
        * `Integrated`: The cipher construction is inherently authenticated
        * `WithDedicatedMac`: An encrypt-then-MAC cipher construction (e.g. AES-CBC-HMAC)
* `NonceTrait` indicating whether a nonce is required
    * `Without`: No nonce/IV may be fed into the encryption process
    * `Required`:  A nonce/IV of a length specific to the cipher is required. By default, a nonce will be auto-generated during encryption.
* `KeyType` denoting how the encryption key is structured
    * `Integrated`: The key consists of a single byte array, from which encryption key and (if required by the algorithm) a mac key is derived.
    * `WithDedicatedMac`: The key consists of an encryption key and a dedicated MAC key to compute the auth tag.


!!! warning inline end
    **NEVER** re-use an IV! Let the Supreme KMP crypto provider auto-generate them!

In addition to runtime checks for matching algorithms and parameters, 
algorithms, keys, and sealed boxes need matching characteristics to be used with each other.
This approach does come with one caveat: It forces you to know what you are dealing with.
Luckily, there is a very effective remedy: [contracts](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.contracts/).

#### Contracts
The Supreme KMP crypto provider makes heavy use of contracts, to communicate type information to the compiler.
Every one of the following subsections has their own part on contracts.
<br>
All contracts can be combined, meaning it is possible to steadily narrow down the properties of an object.

* `isAuthenticated()`
    * if `true`, smart-casts the object's AuthCapability to `AuthCapability.Authenticated<*>`
    * if `false` smart-casts the object's AuthCapability to `AuthCapability.Unauthenticated`
* `hasDedicatedMac()`
    * if `true`, smart-casts the object's
        * KeyType to `KeyType.WithDedicatedMac`
        * AuthCapability to `AuthCapability.Authenticated.WithDedicatedMac`
    * if `false`, smart-casts the object's 
        * AuthCapability to a union type of `SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.Integrated` and `AuthCapability.Unauthenticated`
        * KeyType to `KeyType.Integrated`
* `requiresNonce()`
    * if `true` smart-casts the object's NonceTrait  to `NonceTrait.Required`
    * if `false` smart-casts the object's NonceTrait to `NonceTrait.Without`

In addition, there's `isIntegrated()`, which is only defined for authenticated objects:

* if `true`, smart-casts the object's
    * AuthCapability to `SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.Integrated>`
    * KeyType to `KeyType.Integrated`
* if `false`, smart-casts the object's
    * KeyType to `KeyType.WithDedicatedMac`
    * AuthCapability to `AuthCapability.Authenticated.WithDedicatedMac`


### Algorithms
The foundation of symmetric encryption is the class `SymmetricEncryptionAlgorithm`. Every operation and all related data classes
need a reference to a specific `SymmetricEncryptionAlgorithm`.
Cryptographic algorithms have various obvious properties, such as the underlying cipher
(AES and ChaCha branch off `SymmetricEncryptionAlgorithm` at the root level), `name`, and `keySize`.
Taking all [characteristics](#characteristics) into account results in the following class definition:

The type parameters are `A : AuthCapability<K>`, `I : NonceTrait`, and `K : KeyType`.

As can be seen, this leaves quite some degrees of freedom, especially for AES-based encryption algorithms, which do exhaust
this space. The following algorithms are implemented:

* `SymmetricEncryptionAlgorithm.ChaCha20Poly1305`
* `SymmetricEncryptionAlgorithm.AES_128.GCM`
* `SymmetricEncryptionAlgorithm.AES_192.GCM`
* `SymmetricEncryptionAlgorithm.AES_256.GCM`
* `SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_1`
* `SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_256`
* `SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_384`
* `SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_512`
* `SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_1`
* `SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_256`
* `SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_384`
* `SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_512`
* `SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_1`
* `SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_256`
* `SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_384`
* `SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_512`
* `SymmetricEncryptionAlgorithm.AES_128.WRAP.RFC3394`
* `SymmetricEncryptionAlgorithm.AES_192.WRAP.RFC3394`
* `SymmetricEncryptionAlgorithm.AES_256.WRAP.RFC3394`
* `SymmetricEncryptionAlgorithm.AES_128.CBC.PLAIN`
* `SymmetricEncryptionAlgorithm.AES_192.CBC.PLAIN`
* `SymmetricEncryptionAlgorithm.AES_256.CBC.PLAIN`
* `SymmetricEncryptionAlgorithm.AES_128.ECB`
* `SymmetricEncryptionAlgorithm.AES_192.ECB`
* `SymmetricEncryptionAlgorithm.AES_256.ECB`

### Baseline Usage
Once you know decided on an encryption algorithm, encryption itself is straight-forward:

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-symmetric"
```

1. Symmetric encryption still returns `KmmResult`; `getOrThrow()` explicitly surfaces errors.

Encrypted data is always structured and the individual components are easily accessible:
```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-symmetric-components"
```

Decrypting data received from external sources is also straight-forward:
```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-symmetric-external"
```

### Custom AES-CBC-HMAC
Supreme supports AES-CBC with customizable HMAC to provide AEAD.
This is supported across all _Supreme_ targets and works as follows:
In addition, it is possible to customise AES-CBC-HMAC by freely defining which data gets fed into the MAC.
There are also no constraints on the MAC key length, except that it must not be empty:

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-cbc-hmac"
```

#### Contracts
Encryption algorithms feature one specific pair on contract-powered functions to determine the type of the cipher.
While this knowledge of this property is purely informational, it might still come in handy:

* `isBlockCipher()` smart-casts the algorithm to `BlockCipher` if true and `StreamCipher` otherwise.
* `isStreamCipher()` smart-casts the algorithm to `StreamCipher` if true and `BlockCipher` otherwise.

### Symmetric Keys
Symmetric keys share the same characteristics as symmetric encryption algorithms, to ensure that keys can only be used
with compatible algorithms.

#### Generating, Importing, and Exporting
The main function for key generation is `SymmetricEncryptionAlgorithm.randomKey()`.
This is available even without detailed type information.
For algorithms with a dedicated MAC key, pass `macKeyLength`, as shown in the [custom AES-CBC-HMAC example](#custom-aes-cbc-hmac).

!!! Note inline end
    Parameters and properties of the different key types are deliberately named distinctly and the functions are intentionally only available, if enough
    type information about the algorithm is available. `hasDedicatedMac` is available on keys too!!

It is, of course, possible to access the raw key bytes to export them. Depending on the key type, these are:

* `encryptionKey` and `macKey` for symmetric keys with a dedicated MAC key
* `secretKey` for symmetric key which only use a single key

Importing keys is also straight-forward. For encryption algorithms with a single key (and **only** for those),
simply call `SymmetricEncryptionAlgorithm.keyFrom(secretKey: ByteArray)`.
In case of an AEAD algorithm with a dedicated MAC key, call `keyFrom(encryptionKey: ByteArray, macKey: ByteArray)`.


??? warning "Danger Zone"
    It is possible to manually generate a nonce/IV for algorithms that require an IV/nonce. However, you typically don't need this
    since IVs/nonces are auto-generated when encrypting. If you insist, you can call `SymmetricEncryptionAlgorithm.randomNonce()`
    on algorithms that require a nonce. You must, however, explicitly add an opt-in for `@HazardousMaterials`!.
    <br>
    If you really want to feed a manually generated nonce/IV into the encryption process, call `andPredefinedNonce(nonce: ByteArray)`
    on a symmetric key object, prior to calling `encrypt(data: ByteArray)`.

### Sealed Boxes and Decryption
Sealed boxes represent encrypted data. There's more to the ciphertext bytes to encrypted data. Most notably the nonce/IV, for
algorithms which require them. In Signum's data model, the algorithm is also part of a sealed box in order to match characteristics.
Yet, sealed boxes are a bit more relaxed. They don't really care for whether an AEAD algorithm requires a dedicated MAC key
or not. Hence, there is no contract-backed function `hasDedicatedMacKey()`.


!!! tip inline end
    If you want to decrypt external data and don't need to pass it around as a `SealedBox`,
    use `SymmetricKey.decrypt` rather than `SealedBox.decrypt`!

Decryption is possible in two ways: On the one hand, you can create a `SealedBox` by calling `SymmetricEncryptionAlgorithm.sealedBox` and then call `.decrypt(key)` on it.
Alternatively, it is possible to directly call `SymmetricKey.decrypt()` and pass nonce/IV (if any), ciphertext bytes, auth tag (if any) and additional authenticated data (if any).
The first variant will allow for arbitrary combinations of characteristics for convenience.
The second option, however, will only allow passing a nonce/IV if the algorithm associated with a symmetric key
has the corresponding characteristic.
The same holds for the auth tag and additional authenticated data.


## Asymmetric Encryption
Asymmetric encryption using RSA is supported, although the Supreme KMP crypto currently does not yet support hardware-backed
management of key material.
Hence, it is possible to create ephemeral RSA keys and use those, or import RSA keys.

### Encryption and Decryption API

The API is based on the same paradigm as the signer/verifier tandem. To encrypt data under an RSA public key, three steps are necessary:
* Reference any of the pre-configured asymmetric encryption algorithm such as `AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256` (see [Supported Algorithms and Paddings](#supported-algorithms-and-paddings)).
* Invoke `encryptorFor(rsaPublicKey)` on it to create an `Encryptor`.
* Call `encrypt(data)` and receive encrypted bytes

Decryption works analogously:
* Reference any of the pre-configured asymmetric encryption algorithm such as `AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256` (see [Supported Algorithms and Paddings](#supported-algorithms-and-paddings)).
* Invoke `decryptorFor(rsaPrivateKey)` on it to create a `Decryptor`.
* Call `decrypt(data)` and recover the plain bytes

!!! tip inline end
    The JVM and Android targets allow for optionally specifying a JCA provider name:
    Pass a configuration lambda to `decryptorFor(key)` or `encryptorFor(key.publicKey)` and set `provider` to the desired installed JCA provider name.
    This works the same for encryptors.

RSA encryption and decryption are suspending and return `KmmResult`; encryptor/decryptor creation returns the object directly.

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-rsa-encryption"
```
Textbook RSA (without padding; represented as `RSAPadding.NONE`) is supported, as is the vulnerable PKCS1 padding scheme.
Both require a `HazardousMaterials` opt-in, as the latter should only be used to recover ciphertexts created by legacy systems
and the former should only ever be used as a low-level primitive (usually for experiments but never in production)

### Supported Algorithms and Paddings
As of now, RSA encryption is supported, and the following paddings can be used:

* `RSAPadding.NONE`
* `RSAPadding.PKCS1`
* `RSAPadding.OAEP.SHA1`
* `RSAPadding.OAEP.SHA256`
* `RSAPadding.OAEP.SHA384`
* `RSAPadding.OAEP.SHA512`

For convenience, pre-configured `AsymmetricEncryptionAlgorithm` instances exist for each supported algorithm:

* `AsymmetricEncryptionAlgorithm.RSA.NoPadding`
* `AsymmetricEncryptionAlgorithm.RSA.Pkcs1Padding`
* `AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA1`
* `AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256`
* `AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA384`
* `AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA512`

## Hybrid Public Key Encryption

The Supreme KMP crypto provider includes [HPKE (RFC 9180)](https://www.rfc-editor.org/rfc/rfc9180), combining key encapsulation, HKDF and authenticated encryption.
Instead of manually wiring ECDH and symmetric encryption together, pick a suite and let HPKE derive its keys and nonces.

!!! tip
    HPKE is part of `at.asitplus.signum:supreme:1.0.0`. Check out the [API docs](dokka/supreme/at.asitplus.signum.supreme.asymmetric/-h-p-k-e/index.html) for all parameters.

### Supported Suites

Built-in DHKEM implementations support P-256/HKDF-SHA256, P-384/HKDF-SHA384 and P-521/HKDF-SHA512.
The suite KDF can be HKDF-SHA256, HKDF-SHA384 or HKDF-SHA512.
AEAD choices are AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305. `EXPORT_ONLY` derives secrets without encrypting messages.

!!! warning
    The X25519 and X448 KEM properties currently throw `UnsupportedCryptoException`. Their names in the API do not mean these algorithms are implemented!
    The implementation provides no transport, public-key trust validation or replay policy. Applications must supply those.

### One Message

Generate a recipient key pair, choose the same suite and `info` on both sides, and transmit the encapsulated secret alongside the ciphertext.
`aad` authenticates cleartext protocol metadata; it must match on both sides too.
All operations below are suspending and return direct values. Invalid parameters or failed authentication throw.

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/HpkeExamples.kt:hpke-base"
```

Base mode authenticates the ciphertext to the recipient, but does not establish the sender's identity. Obtain the recipient's public key through a trusted mechanism before encrypting.

### Multiple Messages

For multiple messages, keep the sender and receiver contexts. Each context maintains its own sequence counter and derives the next nonce automatically:

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/HpkeExamples.kt:hpke-context"
```

Process messages in the same order on both sides. Contexts are mutable: do not share them between concurrent callers. This API does not serialize or persist contexts, reorder messages, or provide a replay cache. Failed opening does not advance the receiver's sequence counter; decide how your protocol handles such a failure. The implementation throws `MessageLimitReachedError` when the sequence limit is reached. Discard the context after that error; do not attempt to reuse it.

### Pre-Shared Keys and Sender Authentication

PSK mode additionally binds a pre-shared key and its identifier. Auth mode binds the sender's key pair. AuthPSK combines both:

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/HpkeExamples.kt:hpke-psk-auth"
```

The implementation requires at least 32 PSK bytes and a nonempty PSK identifier, and rejects inconsistent PSK/identifier inputs. The fixed PSK in this test is only a fixture. Use a secret established by your protocol, and validate the sender public key before treating Auth mode as an identity claim. These modes also have `Setup…S`/`Setup…R` context variants for multiple messages.

### Exporting Secrets

The exporter derives matching application secrets on each side, including with an export-only suite:

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/HpkeExamples.kt:hpke-export"
```

Use a distinct exporter context for each purpose. `EXPORT_ONLY` rejects `Seal` and `Open`. Sender/receiver export helpers exist for Base, PSK, Auth and AuthPSK; encryption contexts also expose `Export`.

### Keys and Implementation Limits

The built-in DHKEM can generate random key pairs and deterministically derive them using `DeriveKeyPair(ikm)`. The latter requires suitably random input key material; a password is not sufficient.
Public-key serialization uses uncompressed ANSI X9.63 points. DHKEM also exposes raw private-key serialization, whose current implementation requires an in-memory `EcdsaPrivateKey.WithPublicKey`; it cannot export a hardware-backed private value.

HPKE exposes interfaces for KEM, KDF and AEAD implementations, but custom implementations must satisfy RFC 9180's requirements themselves. A named suite does not add algorithms absent from the underlying platform/provider. The supplied workflows are checked on the JVM; platform restrictions still apply to platform-specific key material.

## Key Derivation / Key Stretching

The Supreme KMP crypto provider implements the following key derivation functions:

* _HKDF_ as per [RFC 5869](https://tools.ietf.org/html/rfc5869)
* _PBKDF2_ in accordance with [RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018)
* _scrypt_ in accordance with [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914)

Usage is the same across implementations:

1. Instantiate a `KDF` implementation using algorithm-specific parameters as per the respective RFCs. These are:
    * HKDF comes predefined for the SHA-1 and SHA-2 family of hash functions as `HKDF.SHA1`..`HKDF.SHA512`. Pass `info` bytes to obtain a fully instantiated `WithInfo` object:  
    `HKDF.SHAXXX(info = ...)` 
    * PBKDF2 comes predefined for HMAC based on the SHA-1 and SHA-2 family of hash functions as `PBKDF2.HMAC_SHA1`..`PBKDF2.HMAC_SHA512`. Pass the number of `iterations` is required to obtain a `WithIterations` object:  
    `PBKDF2.HMAC_SHAXXX(iterations = ...)`
    * An scrypt instance can be configured as desired:  
    `SCrypt(cost, parallelization, blockSize)`.
2. Invoke `deriveKey(salt, inputKeyMaterial, derivedKeyLength)` to obtain a derived key of length `derivedKeyLength` based on `inputKeyMaterial` and the provided `salt`.

`deriveKey` is suspending and returns the derived bytes directly; failures throw. HKDF additionally exposes the suspending `extractStep` and `expandStep` functions.

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-kdf"
```

## Attestation

The Android KeyStore offers key attestation certificates for hardware-backed keys.
These certificates are exposed by the signer's `.attestation` property.

For iOS, Apple does not provide this capability, but rather supports app attestation.
We therefore piggy-back onto iOS app attestation to provide a home-brew "key attestation" scheme.
The guarantees are different: you are trusting the OS, not the actual secure hardware;
and you are trusting that our library properly interfaces with the OS.
On a technical level, it works as follows:

!!! note inline end
    This section assumes in-depth knowledge of how an Apple attestation statement is created and validated,
    as described in the [Apple Developer Documentation on AppAttest](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server).

We make use of the fact that verification of `clientHashData` is purely up to the back-end.
Hence, we create an attestation key, immediately afterwards create a P-256 key inside the secure enclave, and compute
`clientHashData` over both the nonce obtained from the back-end **and** the public key bytes of the freshly created, SE-protected
EC key.
The iOS attestation type hence includes an attestation statement, the challenge, and the public key, so that the back-end
can easily verify the attestation result based on Apple's AppAttest service and the public key bytes, hence emulating
key attestation. The server must validate the App Attest statement and the binding to the expected challenge and public key; this does not turn App Attest into Apple hardware key attestation.

The JVM also "supports" a custom attestation format. By default, it is rather nonsensical.
However, if you plug an HSM that supports attestation to the JCA, you can make use of it.

The [feature matrix](features.md) also contains remarks on attestation, while
details on the attestation format can be found in the corresponding [API documentation](dokka/indispensable/at.asitplus.signum.indispensable/-attestation/index.html).

## Key Agreement

!!! bug inline end
    The Android OS has a bug related to key agreement in hardware. See [important remarks](features.md#android-key-agreement) on key agreement!

In general, key agreement requires one private and _n_ public values. Key distribution/exchange may happen by any means and
is not modelled in Signum.
In addition, iOS only supports ECDH key agreement, hence only ECDH key agreement with a single public value is supported.
Private key agreement material is usually generated locally (preferably in hardware), as outlined in the key generation subsection
on this matter. However, it is also possible to import an EC private key.

On iOS and Android (starting with Android&nbsp;12), key agreement is possible in hardware and can
require biometric authentication for hardware-backed keys. Custom biometric prompt text can be set
in the same manner as [for signing](#signature-creation).

!!! warning
    Key generated using Supreme &leq;0.6.4 don't have the key agreement purpose set and cannot be used for key agreement.
    Regenerate such keys, if you want to use them for key agreement:
    ```kotlin
    --8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-key-agreement-purpose"
    ```


!!! tip inline end
    To generate an ephemeral private value for ECDH key agreement, simply invoke `KeyAgreementPrivateValue.ECDH.Companion.Ephemeral()`.
    Every `KeyAgreementPrivateValue` comes with the corresponding public value attached. This may come in handy for testing.

Once a private and a public value have been obtained, simply call `theOneValue.keyAgreement(theOtherValue)`.
The `keyAgreement()` extension function is present on both `KeyAgreementPublicValue` and `KeyAgreementPrivateValue`, thus making it irrelevant
whether the function is invoked on the public value or on the private value.
Key agreement is suspending and returns a `ByteArray` directly. Feed this raw secret into a suitable KDF with protocol-specific context before using it as an application key.

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-agreement"
```
