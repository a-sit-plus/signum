![Signum Supreme](assets/supreme-dark-large.png#only-light) ![Signum Supreme](assets/supreme-light-large.png#only-dark)

[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus.signum/supreme?label=maven-central)](https://mvnrepository.com/artifact/at.asitplus.signum/supreme)

# **Supreme** KMP Crypto Provider

This [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library provides platform-independent data
types and functionality related to crypto and PKI applications:

* **Multiplatform ECDSA and RSA Signer and Verifier** &rarr; Check out the included [CMP demo App](https://github.com/a-sit-plus/signum/tree/main/demoapp) to see it in
  action
* Biometric Authentication on Android and iOS without Callbacks or Activity Passing** (✨Magic!✨)
* Support Attestation on Android and iOS
* Multiplatform, hardware-backed ECDH key agreement

!!! tip
    **Do check out the full API docs [here](dokka/supreme/index.html)**!

## Using it in your Projects

This library was built for [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html). Currently, it targets
the JVM, Android and iOS.

Simply declare the desired dependency to get going:

```kotlin 
implementation("at.asitplus.signum:supreme:$supreme_version")
```

## Key Design Principles
The Supreme KMP crypto provider works differently than JCA. It uses a `Provider` to manage private key material and create `Signer` instances,
and a `Verifier`, that is instantiated on a `SignatureAlgorithm`, taking a `CryptoPublicKey` as parameter.
In addition, creating ephemeral keys is a dedicated operation, decoupled from a `Provider`.
The actual implementation of cryptographic functionality is delegated to platform-native implementations.

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
