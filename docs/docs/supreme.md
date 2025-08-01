![Signum Supreme](assets/supreme-dark-large.png#only-light) ![Signum Supreme](assets/supreme-light-large.png#only-dark)

[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus.signum/supreme?label=maven-central)](https://mvnrepository.com/artifact/at.asitplus.signum/supreme)

# **Supreme** KMP Crypto Provider

This [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library provides platform-independent data
types and functionality related to crypto and PKI applications:

* Multiplatform ECDSA and RSA Signer and Verifier &rarr; Check out the included [CMP demo App](https://github.com/a-sit-plus/signum/tree/main/demoapp) to see it in
  action
* Multiplatform AES and ChaCha20-Poly1503
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

```kotlin 
implementation("at.asitplus.signum:supreme:$supreme_version")
```

## Key Design Principles
The Supreme KMP crypto provider works differently than the JCA. It uses a `Provider` to manage private key material and create `Signer` instances,
and a `Verifier`, that is instantiated on a `SignatureAlgorithm`, taking a `CryptoPublicKey` as parameter.
In addition, creating ephemeral keys is a dedicated operation, decoupled from a `Provider`.
The actual implementation of cryptographic functionality is delegated to platform-native implementations.

Symmetric encryption follows a similar paradigm, utilising structured representations of ciphertexts and type-safe APIs.
This prevents misuse and mishaps much more effectively than the JCA.

Moreover, the Supreme KMP crypto provider heavily relies on a type-safe DSL for configuration.
This type-safety goes so far as to expose platform-specific configuration options only in platform-specific sources, even when
the actual calls to some DSL-configurable type reads the same as in common code.

!!! warning
    **Do not ignore the results returned by any operation!**  
    We heavily rely  on `KmmResult` to communicate the success or failure of operations. Nothing ever throws!


## Provider Initialization
Currently, we provide only one provider, the `SigningProvider`, which is used to manage signing keys and create signer
instances. Due to limitations of Kotlin, two discrete implementations of the provider exist: one for mobile targets, and
one for the JVM. Their initialization differs.

### iOS and Android
On mobile targets (Android and iOS), simply reference the `PlatformSigningProvider` object, and you're good to go!
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
JKSProvider {
  file { path = keystorePath }
}
```

</td>
<td>

```kotlin
JKSProvider {
  withBackingObject { store = keyStore }
}
```

</td>
</tr>
</table>

Usually, passing pre-initialized keystore is enough to cover even custom `KeyStore` implementations depending on
a specific `SecurityProvider`.
In cases where even more flexibility is needed, it is possible to use `withCustomAccessor{}` and pass a custom
KeyStore-accessor, implementing the `JKSAccessor` interface.

In addition, the `JKSProvider` can be initialized without any backing keystore to create only ephemeral keys, if no
options are passed.


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
prov.createSigningKey(alias = "sig") {
  ec {
      curve = ECCurve.SECP_256_R_1
      digests = setOf(Digest.SHA256)
  }
}
```

</td>
<td>

```kotlin
prov.createSigningKey(alias = "sig") {
  rsa {
    bits = 4096
    digests = setOf(Digest.SHA256)
    paddings = setOf(RSAPAdding.PSS)
  }
}
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
Provider.createSigningKey(ALIAS) {
    ec {
        purposes {
            keyAgreement = true //defaults to false
            signing = true //defaults to true, no impact on key agreement
        } 
    }
}
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
The following snippet is a comprehensive example showcasing this feature set:

```kotlin
val serverChallenge: ByteArray = TODO("This was unpredictably chosen by your server.")
PlatformSigningProvider.createSigningKey(alias = "Swordfish") {
  ec {
    // as supported by iOS and Android in hardware
    curve = ECCurve.SECP_256_R_1
  }
  hardware {
    // you could use PREFERRED if you want the operation to succeed (without hardware backing) on devices that do not support it
    backing = REQUIRED
    attestation { challenge = serverChallenge }
    protection { 
      timeout = 5.seconds
      factors {
        biometry = true
        deviceLock = false
      }  
    }
  }
}
```

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
provider.getSignerForKey("Swordfish") {
  unlockPrompt {
    message = "Authenticate key usage"
    subtitle = "We require your authentication to sign data" //Android-only
    cancelText = "Cancel"
  }
}
```

This configuration will be used for every sign operation as well.
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
CryptoPrivateKey.decodeFromPem(pkcs8)
```

These keys currently cannot be imported into platform-native key stores (Android KeyStore/ iOS KeyChain).
Also, while encrypted keys can be parsed, decryption is currently not natively supported.

#### Creating a Signer from a `CryptoPrivateKey`

!!! note inline end 
    Signers can only be created for private keys that have a public key and/or a curve attached. This may not be the case
    when an EC private key was parsed from SEC1 encoding without curve and public key info.

Given a `CryptoPrivateKey.WithPublicKey` object and a `SignatureAlgorithm` object, a signer can be created as follows:

```kotlin
val signer = sigAlg.signerFor(privateKey)
```

This only works if key and signature algorithm are compatible. Otherwise, it returns `KmmResult.failure`. 
If you have an EC private key at hand without a public key attached, simply convert it to a `CryptoPrivateKey.EC.WithPublicKey` as follows:

```kotlin
privateKey.withCurve(EECurve.SECP_256_R_1)
```

#### Exporting Private Keys

!!! note inline end
    The `exportPrivateKey()` method requires an explicit opt-in for `SecretExposure` to prevent accidental export of private keys

Private keys can be exported (typically to be DER or PEM-encoded) from ephemeral signers and ephemeral key objects as follows:

```kotlin
@OptIn(SecretExposure::class)
val privKey = signer.exportPrivateKey()
```

While all signers feature an `exportPrivateKey()` method, only some signers allow for actually exporting private key material.
Platform-native signers prevent it (i.e. always return a `KmmResult.failure`) when trying to export private keys.
Keys from signers created from a `CryptoPrivateKey` (see above), as well as ephemeral signers can be exported.


## Signature Creation
Regardless of whether a key was freshly created or a pre-existing key way loaded. The result of either operation
is a `Signer`, which can be used as desired.
To sign, simply pass data to sign.
On iOS and Android, it is possible to perform additional optional configuration, such as
setting up an `unlockPrompt`:

```kotlin
signer.sign(data) {
  unlockPrompt {
    message = "Authenticate key usage"
    subtitle = "We require your authentication to sign data" //Android-only
    cancelText = "Cancel"
  }
}
```

## Signature Verification

To verify a signature, obtain a `Verifier` instance using `verifierFor(k: PublicKey)`, either directly on a
`SignatureAlgorithm`, or on one of the specialized algorithms (`X509SignatureAlgorithm`, `CoseAlgorithm`, ...).
A variety of constants, resembling the well-known JCA names, are also available in `SignatureAlgorithm`'s companion.

As an example, here's how to verify a basic signature using a public key:

```kotlin
val publicKey: CryptoPublicKey.EC = TODO("You have this and trust it.")
val plaintext = "You want to trust this.".encodeToByteArray()
val signature: CryptoSignature = TODO("This was sent alongside the plaintext.")
val verifier = SignatureAlgorithm.ECDSAwithSHA256.verifierFor(publicKey).getOrThrow()
val isValid = verifier.verify(plaintext, signature).isSuccess
println("Looks good? $isValid")
```

!!! tip
    Not every platform supports every algorithm parameter. For example, iOS does not support raw ECDSA verification (of pre-hashed data) for curve P-521.
    If you use `.verifierFor`, and this happens, the library will transparently substitute a pure-Kotlin implementation.  
    If this is not desired, you can specifically enforce a platform verifier by using `.platformVerifierFor`.
    That way, the library will only ever act as a proxy to platform APIs (JCA, CryptoKit, etc.), and will not use its own implementations.

You can also further configure the verifier, for example to specify the `provider` to use on the JVM.
To do this, pass a DSL configuration lambda to `verifierFor`/`platformVerifierFor`.

There really is not much more to it. This pattern works the same on all platforms.
Details on how to parse cryptographic material can be found in the [section on decoding](indispensable.md#asn1-engine-addons) in
of the Indispensable module description.


## Ephemeral Keys and Ephemeral Signers
Ephemeral keys and ephemeral signers are not backed by a provider, but are still delegated to platform functionality.
They are just not persisted and work the same across platforms.

To obtain an ephemeral signer, call `Signer.Ephemeral{}` and pass EC or RSA-specific configuration options as you would when creating a key using
the `SigningProvider`.
Alternatively, you can create an ephemeral key using `EphemeralKey{}`(and again, pass algorithm-specific configuration options).
To obtain a signer from this ephemeral key, call `getSigner{}` on it. This, similarly to provider-backed keys, takes
algorithm-specific configuration options, such as a specific hash algorithm or padding, in case more than one was
specified when creating the ephemeral key.

## Digest Calculation
The Supreme KMP crypto provider introduces a `digest()` extension function on the `Digest` class.
For a list of supported algorithms, check out the [feature matrix](features.md#supported-algorithms).

## HMAC Calculation
The Supreme KMP crypto provider introduces a `mac()` extension on the `MAC` class. It takes two arguments:

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
    * if `false` smart-casts the object's AuthCapability to `AuthCapability.Unathenticated`
* `hasDedicatedMac()`
    * if `true`, smart-casts the object's
        * KeyType to `KeyType.WithDedicatedMac`
        * AuthCapability to `AuthCapability.Authenticated.WithDedicatedMac`
    * if `false`, smart-casts the object's 
        * AuthCapability to a union type of `SymmetricEncryptionalgorithm<AuthCapability.Authenticated.Integrated` and `AuthCapability.Unauthenticated`
        * KeyType to `KeyType.Integrated`
* `requiresNonce()`
    * if `true` smart-casts the object's NonceTrait  to `Nonce.Required`
    * if `false` smart-casts the object's NonceTrait to `Nonce.Without`

In addition, there's `isIntegrated()`, which is only defined for objects having the `Authenticated.Integrated` characteristic:

* if `true`, smart-casts the object's
    * AuthCapability to `SymmetricEncryptionalgorithm<AuthCapability.Authenticated.Integrated>`
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

```kotlin
SymmetricEncryptionAlgorithm<out A : AuthCapability<out K>, out I : NonceTrait, out K : KeyType>
```

As can be seen, this leaves quite some degrees of freedom, especially for AES-based encryption algorithms, which do exhaust
this space. As of 01-2025, the following algorithms are implemented:

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
val secret = "Top Secret".encodeToByteArray()
val secretKey = SymmetricEncryptionAlgorithm.ChaCha20Poly1305.randomKey()
val encrypted = secretKey.encrypt(secret).getOrThrow(/*handle error*/)
encrypted.decrypt(secretKey).getOrThrow(/*handle error*/) shouldBe secret
```

Encrypted data is always structured and the individual components are easily accessible:
```kotlin
val nonce = encrypted.nonce
val ciphertext = encrypted.encryptedData
val authTag = encrypted.authTag
val keyBytes = secretKey.secretKey.getOrThrow() /*for algorithms with a dedicated MAC key, there's encryptionKey and macKey*/
```

Decrypting data received from external sources is also straight-forward:
```kotlin
val box = algo.sealedBox.withNonce(nonce).from(ciphertext, authTag).getOrThrow(/*handle error*/)
box.decrypt(preSharedKey, /*also pass AAD*/ externalAAD).getOrThrow(/*handle error*/) shouldBe secret

//alternatively, pass raw data:
preSharedKey.decrypt(nonce, ciphertext, authTag, externalAAD).getOrThrow(/*handle error*/) shouldBe secret
```

### Custom AES-CBC-HMAC
Supreme supports AES-CBC with customizable HMAC to provide AEAD.
This is supported across all _Supreme_ targets and works as follows:
In addition, it is possible to customise AES-CBC-HMAC by freely defining which data gets fed into the MAC.
There are also no constraints on the MAC key length, except that it must not be empty:

```kotlin
val payload = "More matter, with less art!".encodeToByteArray()

//define algorithm parameters
val algorithm = SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_512
    //with a custom HMAC input calculation function
    .Custom(32.bytes) { ciphertext, iv, aad -> //A shorter version of RFC 7518
        aad + iv + ciphertext + aad.size.encodeTo4Bytes()
    }

//any size is fine, really. omitting the override generates a mac key
//of the same size as the encryption key
val key = algorithm.randomKey(macKeyLength = 32.bit)
val aad = Clock.System.now().toString().encodeToByteArray()

val sealedBox = key.encrypt(
    payload,
    authenticatedData = aad,
).getOrThrow(/*handle error*/)

//because everything is structured, decryption is simple
val recovered = sealedBox.decrypt(key, aad).getOrThrow(/*handle error*/)

recovered shouldBe payload //success!

//we can also manually construct the sealed box, if we know the algorithm:
val reconstructed = algorithm.sealedBox.withNonce(sealedBox.nonce).from(
    encryptedData = sealedBox.encryptedData, /*Could also access authenticatedCipherText*/
    authTag = sealedBox.authTag,
).getOrThrow()

val manuallyRecovered = reconstructed.decrypt(
    key,
    authenticatedData = aad,
).getOrThrow(/*handle error*/)

manuallyRecovered shouldBe payload //great success!

//if we just know algorithm and key bytes, we can also construct a symmetric key
reconstructed.decrypt(
    algorithm.keyFrom(key.encryptionKey.getOrThrow(), key.macKey.getOrThrow()).getOrThrow(/*handle error*/),
    aad
).getOrThrow(/*handle error*/) shouldBe payload //greatest success!
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
This always works, even without type information.
For algorithms with a dedicated MAC key, an overloaded variant is available too:
```kotlin
SymmetricEncryptionalgorithm.randomKey(macKeyLength: BitLength = preferredMacKeyLength)
```

!!! Note inline end
    Parameters and properties of the different key types are deliberately named distinctly and the functions are intentionally only available, if enough
    type information about the algorithm is available. `hasDedicatedMac` is available on keys too!!

It is, of course, possible to access the raw key bytes to export the,. Depending on the key type, these are:

* `encryptionKey` and `macKey` for symmetric keys with a dedicated MAC key
* `secretKey` for symmetric key which only use a single key

Importing keys is also straight-forward. For encryption algorithms with a single key (and **only** for those),
simply call `SymmetricEncryptionalgorithm.keyFrom(secretKey: ByteArray)`.
In case of an AEAD algorithm with a dedicated MAC key, call `keyFrom(encryptionKey: ByteArray, macKey: ByteArray)`.


??? warning "Danger Zone"
    It is possible to manually generate a nonce/IV for algorithms that require an IV/nonce. However, you typically don't need this
    since IVs/nonces are auto-generated when encrypting. If you insist, you can call `SymmetricEncryptionAlgorithm.randomKey()`
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

Decryption is possible in two ways: On the on hand, you can create a `SealedBox` by calling `SymmetricEncryptionAlgorithm.sealedBox()` and then call `.decrypt(key)` on it.
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
    ```kotlin
    alg.decryptorFor(key) {
      provider= "BC"
    }
    ```
    This works the same for encryptors.

As with the rest of the API, `KmmResult` is used throughout and the encryption/decryption functions are suspending.
Textbook RSA (without padding; represented as `RsaPadding.NONE`) is supported, as is the vulnerable PKCS1 padding scheme.
Both require a `HazardousMaterials` opt-in, as the latter may only to recover ciphertexts created by legacy systems
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

## Key Derivation / Key Stretching

The Supreme KMP crypto provider implements the following key derivation functions:

* _HKDF_ as per [RFC 5869](https://tools.ietf.org/html/rfc5869)
* _PBKDF2_ in accordance with [RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018)
* _scrpyt_ in accordance with [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914)

Usage is the same across implementations:

1. Instantiate a `KDF` implementation using algorithm-specific parameters as per the respective RFCs. These are:
    * HKDF comes predefined for the SHA-1 and SHA-2 family of hash functions as `HKDF.SHA1`..`HKDF.SHA512`. Pass `info` bytes to obtain a fully instantiated `WithInfo` object:  
    `HKDF.SHAXXX(info = ...)` 
    * PBKDF2 comes predefined for HMAC based on the SHA-1 and SHA-2 family of hash functions as `PBKDF2.HMAC_SHA1`..`PBKDF2.HMAC_SHA512`. Pass the number of `iterations` is required to obtain a `WithIterations` object:  
    `PBKDF2.SHAXXX(iterations = ...)`
    * An scrypt instance can be configured as desired:  
    `SCrypt(cost, parallelization, blockSize)`.
2. Invoke `deriveKey(salt, inputKeyMaterial, derivedKeyLength)` to obtain a derived key of length `derivedKeyLength` based on `inputKeyMaterial` and the provided `salt`.

In line with other APIs, `deriveKey` returns a `KmmResult` indicating either success or failure.
HKDF additionally exposes `extract(salt /*nullable*/, inputKeyMaterial)` and `expand(pseudoRandomKey, info, derivedKeyLength)` functions.

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
key attestation. Strictly speaking, this is a violation of the process described by Apple, but cryptographically, it is
perfectly sound!

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
    Provider.createSigningKey(ALIAS) {
      ec {
        purposes {
          keyAgreement = true //defaults to false
          signing = true //defaults to true, no impact on key agreement
        }
      }
    }
    ```


!!! tip inline end
    To generate an ephemeral private value for ECDH key agreement, simply invoke `KeyAgreementPrivateValue.ECDH.Companion.Ephemeral()`.
    Every `KeyAgreementPrivateValue` comes with the corresponding public value attached. This may come in handy for testing.

Once a private and a public value have been obtained, simply call `theOneValue.keyAgreement(theOtherValue)`.
The `keyAgreement()` extension function is present on both `KeyAgreementPublicValue` and `KeyAgreementPrivateValue`, thus making it irrelevant
whether the function is invoked on the public value or on the private value.
The return value of a key agreement is always a (KmmResult-wrapped) `ByteArray` without additional semantics.
