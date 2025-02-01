<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/docs/assets/signum-light-large.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/docs/assets/signum-dark-large.png">
  <img alt="Signum – Kotlin Multiplatform Crypto/PKI Library and ASN1 Parser + Encoder" src="docs/docs/assets/signum-dark-large.png">
</picture>


# Signum – Kotlin Multiplatform Crypto/PKI Library and ASN1 Parser + Encoder

[![A-SIT Plus Official](https://img.shields.io/badge/A--SIT_Plus-official-005b79?logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNDMuNzYyODYgMTg0LjgxOTk5Ij48ZGVmcz48Y2xpcFBhdGggaWQ9ImEiIGNsaXBQYXRoVW5pdHM9InVzZXJTcGFjZU9uVXNlIj48cGF0aCBkPSJNMCA1OTUuMjhoODQxLjg5VjBIMFoiLz48L2NsaXBQYXRoPjwvZGVmcz48ZyBjbGlwLXBhdGg9InVybCgjYSkiIHRyYW5zZm9ybT0ibWF0cml4KDEuMzMzMzMzMyAwIDAgLTEuMzMzMzMzMyAtNDgyLjI1IDUxNy41MykiPjxwYXRoIGZpbGw9IiMwMDViNzkiIGQ9Ik00MTUuNjcgMjQ5LjUzYy03LjE1LjA4LTEzLjk0IDEtMjAuMTcgMi43NWE1Mi4zMyA1Mi4zMyAwIDAgMC0xNy40OCA4LjQ2IDQwLjQzIDQwLjQzIDAgMCAwLTExLjk2IDE0LjU2Yy0yLjY4IDUuNDEtNC4xNCAxMS44NC00LjM1IDE5LjA5bC0uMDIgNi4xMnYyLjE3YS43MS43MSAwIDAgMCAuNy43M2gxNi41MmMuMzkgMCAuNy0uMzIuNzEtLjdsLjAxLTIuMmMwLTIuNi4wMi01LjgyLjAzLTYuMDcuMi00LjYgMS4yNC04LjY2IDMuMDgtMTIuMDZhMjguNTIgMjguNTIgMCAwIDEgOC4yMy05LjU4IDM1LjI1IDM1LjI1IDAgMCAxIDExLjk2LTUuNTggNTUuMzggNTUuMzggMCAwIDEgMTIuNTgtMS43NmM0LjMyLjEgOC42LjcgMTIuNzQgMS44YTM1LjA3IDM1LjA3IDAgMCAxIDExLjk2IDUuNTcgMjguNTQgMjguNTQgMCAwIDEgOC4yNCA5LjU3YzEuOTYgMy42NCAzIDguMDIgMy4xMiAxMy4wMnYyNC4wOUgzNjIuNGEuNy43IDAgMCAwLS43MS43VjMzNWMwIDguNDMuMDEgOC4wNS4wMSA4LjE0LjIgNy4zIDEuNjcgMTMuNzcgNC4zNiAxOS4yMmE0MC40MyA0MC40MyAwIDAgMCAxMS45NiAxNC41N2M1IDMuNzYgMTAuODcgNi42MSAxNy40OCA4LjQ2YTc3LjUgNzcuNSAwIDAgMCAyMC4wMiAyLjc3YzcuMTUtLjA3IDEzLjk0LTEgMjAuMTctMi43NGE1Mi4zIDUyLjMgMCAwIDAgMTcuNDgtOC40NiA0MC40IDQwLjQgMCAwIDAgMTEuOTUtMTQuNTdjMS42Mi0zLjI2IDMuNzctMTAuMDQgMy43Ny0xNC42OCAwLS4zOC0uMTctLjc0LS41NC0uODJsLTE2Ljg5LS40Yy0uMi0uMDQtLjM0LjM0LS4zNC41NCAwIC4yNy0uMDMuNC0uMDYuNi0uNSAyLjgyLTEuMzggNS40LTIuNjEgNy42OWEyOC41MyAyOC41MyAwIDAgMS04LjI0IDkuNTggMzUuMDEgMzUuMDEgMCAwIDEtMTEuOTYgNS41NyA1NS4yNSA1NS4yNSAwIDAgMS0xMi41NyAxLjc3Yy00LjMyLS4xLTguNjEtLjcxLTEyLjc1LTEuOGEzNS4wNSAzNS4wNSAwIDAgMS0xMS45Ni01LjU3IDI4LjUyIDI4LjUyIDAgMCAxLTguMjMtOS41OGMtMS44Ni0zLjQ0LTIuOS03LjU1LTMuMDktMTIuMmwtLjAxLTcuNDdoODkuMTZhLjcuNyAwIDAgMCAuNy0uNzJ2LTM5LjVjLS4xLTcuNjUtMS41OC0xNC40LTQuMzgtMjAuMDZhNDAuNCA0MC40IDAgMCAwLTExLjk1LTE0LjU2IDUyLjM3IDUyLjM3IDAgMCAwLTE3LjQ4LTguNDcgNzcuNTYgNzcuNTYgMCAwIDAtMjAuMDEtMi43N1oiLz48cGF0aCBmaWxsPSIjY2U0OTJlIiBkPSJNNDE5LjM4IDI4MC42M2gtNy41N2EuNy43IDAgMCAwLS43MS43MXYxNS40MmE4LjE3IDguMTcgMCAwIDAtMy43OCA2LjkgOC4yOCA4LjI4IDAgMCAwIDE2LjU0IDAgOC4yOSA4LjI5IDAgMCAwLTMuNzYtNi45di0xNS40MmEuNy43IDAgMCAwLS43Mi0uNzEiLz48L2c%2BPC9zdmc%2B&logoColor=white&labelColor=white)](https://a-sit-plus.github.io)
[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-brightgreen.svg?style=flat)](http://www.apache.org/licenses/LICENSE-2.0)
[![Kotlin](https://img.shields.io/badge/kotlin-multiplatform-orange.svg?logo=kotlin)](http://kotlinlang.org)
[![Kotlin](https://img.shields.io/badge/kotlin-2.1.0-blue.svg?logo=kotlin)](http://kotlinlang.org)
[![Java](https://img.shields.io/badge/java-17+-blue.svg?logo=OPENJDK)](https://www.oracle.com/java/technologies/downloads/#java11)

[![Maven Central (indispensable)](https://img.shields.io/maven-central/v/at.asitplus.signum/indispensable?label=maven-central%20%28indispensable%29)](https://mvnrepository.com/artifact/at.asitplus.signum/)
[![Maven SNAPSHOT (indispensable)](https://img.shields.io/nexus/snapshots/https/s01.oss.sonatype.org/at.asitplus.signum/indispensable?label=SNAPSHOT%20%28indispensable%29)](https://s01.oss.sonatype.org/content/repositories/snapshots/at/asitplus/signum/indispensable/)  
[![Maven Central (Supreme)](https://img.shields.io/maven-central/v/at.asitplus.signum/supreme?label=maven-central%20%28Supreme%29)](https://mvnrepository.com/artifact/at.asitplus.signum/supreme)
[![Maven SNAPSHOT (Supreme)](https://img.shields.io/nexus/snapshots/https/s01.oss.sonatype.org/at.asitplus.signum/supreme?label=SNAPSHOT%20%28Supreme%29)](https://s01.oss.sonatype.org/content/repositories/snapshots/at/asitplus/signum/supreme/)

</div>

## Kotlin Multiplatform Crypto/PKI Library with ASN1 Parser + Encoder


This [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library provides platform-independent data
types and functionality related to crypto and PKI applications:

* **Multiplatform ECDSA and RSA Signer and Verifier** &rarr; Check out the included [CMP demo App](demoapp) to see it in action
  * **Supports Attestation on iOS and Android**
  * **Biometric Authentication on Android and iOS without Callbacks or Activity Passing** (✨Magic!✨)
* Public Keys (RSA and EC)
* Algorithm Identifiers (Signatures, Hashing)
* X509 Certificate Class (create, encode, decode)
* Certification Request (CSR)
* ObjectIdentifier Class with human-readable notation (e.g. 1.2.9.6245.3.72.13.4.7.6)
* Generic ASN.1 abstractions to operate on and create arbitrary ASN.1 Data
* JOSE-related data structures (JSON Web Keys, JWT, etc…)
* COSE-related data structures (COSE Keys, CWT, etc…)
* Serializability of all ASN.1 classes for debugging **AND ONLY FOR DEBUGGING!!!** *Seriously, do not try to deserialize ASN.1 classes through kotlinx.serialization! Use `decodeFromDer()` and its companions!*
* 100% pure Kotlin BitSet
* Exposes Multibase Encoder/Decoder as an API dependency including [Matthew Nelson's smashing Base16, Base32, and Base64 encoders](https://github.com/05nelsonm/encoding)
* **ASN.1 Parser and Encoder including a DSL to generate ASN.1 structures**

This last bit means that
**you can work with X509 Certificates, public keys, CSRs and arbitrary ASN.1 structures on iOS.**  
The very first bit means that you can verify signatures on the JVM, Android and on iOS.

### Do check out the full manual with examples and API docs [here](https://a-sit-plus.github.io/signum/)!
This README provides just an overview.
The full manual is more comprehensive, has separate sections for each module, provides examples, and a full API documentation.

## Using it in your Projects

This library was built for [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html). Currently, it targets
the JVM, Android and iOS.
It consists of four modules, each of which is published on maven central:


|                                                                                                                                      Name                                                                                                                                      | Info                                                                                                                                                                                                                                                               |
|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  <picture> <source media="(prefers-color-scheme: dark)" srcset="docs/docs/assets/asn1-light.png">   <source media="(prefers-color-scheme: light)" srcset="docs/docs/assets/asn1-dark.png">   <img alt="Indispensable ASN.1" src="docs/docs/assets/asn1-dark.png"> </picture>   | **Indispensable ASN.1** module containing the most sophisticated KMP ASN.1 engine in the known universe. kotlinx-* dependencies aside, it only depends only on [KmmResult](https://github.com/a-sit-plus/kmmresult) for extra-smooth iOS interop.                  | 
|     <picture> <source media="(prefers-color-scheme: dark)" srcset="docs/docs/assets/core-light.png">   <source media="(prefers-color-scheme: light)" srcset="docs/docs/assets/core-dark.png">   <img alt="Indispensable" src="docs/docs/assets/core-dark.png"> </picture>      | **Indispensable** base module containing the cryptographic data structures, algorithm identifiers, X.509 certificate, …. Depends on the ASN.1 engine.                                                                                                              | 
| <picture> <source media="(prefers-color-scheme: dark)" srcset="docs/docs/assets/josef-light.png">   <source media="(prefers-color-scheme: light)" srcset="docs/docs/assets/josef-dark.png">   <img alt="Indispensable Josef" src="docs/docs/assets/josef-dark.png"> </picture> | **Indispensable Josef** JOSE add-on module containing JWS/E/T-specific data structures and extensions to convert from/to types contained in the base module. Includes all required kotlinx-serialization magic to allow for spec-compliant de-/serialization.      | 
| <picture> <source media="(prefers-color-scheme: dark)" srcset="docs/docs/assets/cosef-light.png">   <source media="(prefers-color-scheme: light)" srcset="docs/docs/assets/cosef-dark.png">   <img alt="Indispensable Cosef" src="docs/docs/assets/cosef-dark.png"> </picture> | **Indispensable Cosef** COSE add-on module containing all COSE/CWT-specific data structures and extensions to convert from/to types contained in the base module. Includes all required kotlinx-serialization magic to allow for spec-compliant de-/serialization. |
|    <picture> <source media="(prefers-color-scheme: dark)" srcset="docs/docs/assets/supreme-light.png">   <source media="(prefers-color-scheme: light)" srcset="docs/docs/assets/supreme-dark.png">   <img alt="Supreme" src="docs/docs/assets/supreme-dark.png"> </picture>    | **Supreme** KMP crypto provider implementing hardware-backed signature creation and verification across mobile platforms (Android KeyStore / iOS Secure Enclave) and JCA compatibility (on the JVM).                                                               | 

This separation keeps dependencies to a minimum, i.e. it enables including only JOSE-related functionality, if COSE is irrelevant.
More importantly, in a JVM, iOS, or Android-only project, it allows for processing cryptographic material without imposing the inclusion of a crypto provider.

Simply declare the desired dependency to get going:

```kotlin 
implementation("at.asitplus.signum:indispensable:$version")
```

```kotlin 
implementation("at.asitplus.signum:indispensable-josef:$version")
```

```kotlin 
implementation("at.asitplus.signum:indispensable-cosef:$version")
```

```kotlin 
implementation("at.asitplus.signum:supreme:0.2.0")
```

## Rationale
Looking for a KMP cryptography framework, you have undoubtedly come across
[cryptography-kotlin](https://github.com/whyoleg/cryptography-kotlin). So have we and it is a powerful
library, supporting more platforms and more cryptographic operations than Signum Supreme.
This begs the question: Why implement another, incompatible
cryptography framework from scratch? The short answer is: Signum and cryptography-kotlin pursue different goals and priorities.<br>
cryptography-kotlin strives for covering a wide range of targets and a broad range of operations based on a flexible provider architecture.
Signum, on the other hand, focuses on tight platform integration (**including hardware-backed crypto and attestation!**),
and comprehensive ASN.1, JOSE, and COSE support.

<details>
<summary>More…</summary>

Signum was born from the need to have cryptographic data structures available across platforms, such as public keys, signatures,
certificates, CSRs, as well as COSE and JOSE data. Hence, we needed a fully-featured ASN.1 engine and mappings from
X.509 to COSE and JOSE datatypes. We required comprehensive ASN.1 introspection and builder capabilities across platforms.
Most notably, Apple has been notoriously lacking anything even remotely usable
and [SwiftASN1](https://github.com/apple/swift-asn1) was out of the question for a couple of reasons.
Most notably, it did not exist, when we started work on Signum.
As it stands now, our ASN.1 engine can handle almost anything you throw at it, in some areas even exceeding Bouncy Castle!
cryptography-kotlin only added basic ASN.1 capabilities over a year after Signum's development started.
<br>
We are also unaware of any other library offering comprehensive JOSE and COSE data structures based on kotlinx-serialization.
Hence, we implemented those ourselves, with first-class interop to our generic cryptographic data structures.
We also support platform-native interop meaning that you can easily convert a Json Web Key to a JCA key or even a `SecKeyRef`.

Having actual implementations of cryptographic operations available was only second on our list of priorities. From the
get-go, it was clear that we wanted the tightest possible platform integration on Android and iOS, including hardware-backed
storage of key material and in-hardware execution of cryptographic operations whenever possible.
We also needed platform-native attestation capabilities (and so will you sooner or later, if you are doing anything
mission-critical on mobile targets!).
While this approach does limit the number of available cryptographic operations, it also means that all cryptographic operations
involving secrets (e.g. private keys) provide the same security guarantees as platform-native implementations do &mdash;
**because they are the same** under the hood. Most notably: private keys never leave the platform and **hardware-backed private keys
never even leave the hardware crypto modules**!<br>
This tight integration and our focus on mobile comes at the cost of the **Supreme KMP crypto provider only supporting JVM,
Android, and iOS**.
cryptography-kotlin, on the other hand allows you to perform a wider range of cryptographic functions an all KMP targets,
Most prominently, it already supports RSA encryption, key stretching, and key derivation, which Signum currently lacks.
On the other hand, cryptography-kotlin currently offers neither hardware-backed crypto, nor attestation capabilities.

</details>

The following table provides a detailed comparison between Signum and cryptography-kotlin.

|                             | Signum               | cryptography-kotlin       |
|-----------------------------|----------------------|---------------------------|
| Digital Signatures          | ✔ (ECDSA, RSA)       | ✔ (ECDSA, RSA)            |
| Symmetric Encryption        | ✔ (AES + ChaChaPoly) | ✔ (AES)                   |
| Public-Key Encryption       | ✗                    | ✔ (RSA)                   |
| Digest                      | ✔ (SHA-1, SHA-2)     | ✔ (MD5, SHA-1, SHA-2)     |
| MAC                         | ✔ (HMAC)             | ✔ (HMAC)                  |
| Key Agreement               | ✔ (ECDH)             | ✔ (ECDH)                  |
| KDF/PRF/KSF                 | ✗                    | ✔ (PBKDF2, HKDF)          |
| Hardware-Backed Crypto      | ✔                    | ✗                         |
| Attestation                 | ✔                    | ✗                         |
| Fully-Features ASN.1 Engine | ✔                    | ✗                         |
| COSE                        | ✔                    | ✗                         |
| JOSE                        | ✔                    | ✗                         |
| Provider Targets            | JVM, Android, iOS    | All KMP-supported targets |


## _Supreme_ Demo Reel
The _Supreme_ KMP crypto provider works differently from JCA. Configuration is type-safe, more expressive and more concise,
meaning you'll end up with less code. **Nothing throws! Do not discard the results returned from any operation!**

### Signature Creation

To create a signature, obtain a `Signer` instance.
You can do this using `Signer.Ephemeral` to create a signer for a throwaway keypair:
```kotlin
val signer = Signer.Ephemeral {}.getOrThrow()
val plaintext = "You have this.".encodeToByteArray()
val signature = signer.sign(plaintext).signature
println("Signed using ${signer.signatureAlgorithm}: $signature")
```

If you want to create multiple signatures using the same ephemeral key, you can obtain an `EphemeralKey` instance, then create signers from it:
```kotlin
val key = EphemeralKey { rsa {} }.getOrThrow()
val sha256Signer = key.getSigner { rsa { digest = Digests.SHA256 } }.getOrThrow()
val sha384Signer = key.getSigner { rsa { digest = Digests.SHA384 } }.getOrThrow()
```

The instances can be configured using the configuration DSL.
Any unspecified parameters use sensible, secure defaults.

#### Platform Signers

On Android and iOS, signers using the systems' secure key storage can be retrieved.
To do this, use `PlatformSigningProvider` (in common code), or interact with `AndroidKeystoreProvider`/`IosKeychainProvider` (in platform-specific code).

New keys can be created using `createSigningKey(alias: String) { /* configuration */ }`,
and signers for existing keys can be retrieved using `getSignerForKey(alias: String) { /* configuration */ }`.

For example, creating an elliptic-curve key over P256, stored in secure hardware, and with key attestation using a random challenge provided by your server, might be done like this:
```kotlin
val serverChallenge: ByteArray = TODO("This was unpredictably chosen by your server.")
PlatformSigningProvider.createSigningKey(alias = "Swordfish") {
  ec {
    // you don't even need to specify the curve (P256 is the default) but we'll do it for demonstration purposes
    curve = ECCurve.SECP_256_R_1
    // you could specify the supported digests explicitly - if you do not, the curve's native digest (for P256, this is SHA256) is supported
  }
  // see https://a-sit-plus.github.io/signum/supreme/at.asitplus.signum.supreme.sign/-platform-signing-key-configuration-base/-secure-hardware-configuration/index.html
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

If this operation succeeds, it returns a `Signer`. The same `Signer` could later be retrieved using `PlatformSigningProvider.getSignerForKey(alias: String)`.

When you use this `Signer` to sign data, the user would be prompted to authorize the signature using an enrolled fingerprint, because that's what you specified when creating the key.
You can configure the authentication prompt:
```kotlin
val plaintext = "A message".encodeToByteArray()
val signature = signer.sign(plaintext) { 
  unlockPrompt {
    message = "Signing a message to Bobby"
  }
}.signature
```
... but you cannot change the fact that you configured this key to need biometry. Consider this when creating your keys.

On the JVM, no native secure hardware storage is available.
File-based keystores can be accessed using `JKSProvider { file { /* ... */ } }`.
Other keystores can be accessed using `JKSProvider { withBackingObject{ /* ... */ } }` or `JksProvider { customAccessor{ /* ... */ } }`.
For more details, please refer to the provider's [configuration options](https://a-sit-plus.github.io/signum/dokka/supreme/at.asitplus.signum.supreme.os/-j-k-s-provider-configuration/index.html).

#### Key Attestation

The Android KeyStore offers key attestation certificates for hardware-backed keys.
These certificates are exposed by the signer's `.attestation` property.

For iOS, Apple does not provide this capability.
We instead piggy-back onto iOS App Attestation to provide a home-brew "key attestation" scheme.
The guarantees are different: you are trusting the OS, not the actual secure hardware; and you are trusting that our library properly interfaces with the OS.
Attestation types are serializable for transfer, and correspond to those in Indispensable's attestation module.

### Signature Verification

To verify a signature, obtain a `Verifier` instance using `verifierFor(k: PublicKey)`, either directly on a `SignatureAlgorithm`, or on one of the specialized algorithms (`X509SignatureAlgorithm`, `CoseAlgorithm`, ...).
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

Or here's how to validate a X.509 certificate:
```kotlin
val rootCert: X509Certificate = TODO("You have this and trust it.")
val untrustedCert: X509Certificate = TODO("You want to verify that this is trustworthy.")

val verifier = untrustedCert.signatureAlgorithm.verifierFor(rootCert.publicKey).getOrThrow()
val plaintext = untrustedCert.tbsCertificate.encodeToDer()
val signature = untrustedCert.signature
val isValid = verifier.verify(plaintext, signature).isSuccess
println("Certificate looks trustworthy: $isValid")
```

#### Platform Verifiers

Not every platform supports every algorithm parameter. For example, iOS does not support raw ECDSA verification (of pre-hashed data) for curve P-521.
If you use `.verifierFor`, and this happens, the library will transparently substitute a pure-Kotlin implementation.

If this is not desired, you can specifically enforce a platform verifier by using `.platformVerifierFor`.
That way, the library will only ever act as a proxy to platform APIs (JCA, CryptoKit, etc.), and will not use its own implementations.

You can also further configure the verifier, for example to specify the `provider` to use on the JVM.
To do this, pass a DSL configuration lambda to `verifierFor`/`platformVerifierFor`.

```kotlin
val publicKey: CryptoPublicKey.EC = TODO("You have this.")
val plaintext: ByteArray = TODO("This is the message.")
val signature: CryptoSignature.EC = TODO("And this is the signature.")
    
val verifier = SignatureAlgorithm.ECDSAwithSHA512
    .platformVerifierFor(publicKey) { provider = "BC"} /* specify BouncyCastle */
    .getOrThrow()
val isValid = verifier.verify(plaintext, signature).isSuccess
println("Is it trustworthy? $isValid")
```

## ASN.1 Demo Reel

Classes like `CryptoPublicKey`, `X509Certificate`, `Pkcs10CertificationRequest`, etc. all
implement `Asn1Encodable` and their respective companions implement `Asn1Decodable`.
Which means that you can do things like parsing and examining certificates, creating CSRs, or transferring key
material.

### Certificate Parsing


```kotlin
val cert = X509Certificate.decodeFromDer(certBytes)

when (val pk = cert.publicKey) {
    is CryptoPublicKey.EC -> println(
        "Certificate with serial no. ${
            cert.tbsCertificate.serialNumber
        } contains an EC public key using curve ${pk.curve}"
    )

    is CryptoPublicKey.RSA -> println(
        "Certificate with serial no. ${
            cert.tbsCertificate.serialNumber
        } contains a ${pk.bits.number} bit RSA public key"
    )
}

println("The full certificate is:\n${Json { prettyPrint = true }.encodeToString(cert)}")

println("Re-encoding it produces the same bytes? ${cert.encodeToDer() contentEquals certBytes}")
```

Which produces the following output:
> Certificate with serial no. 19821EDCA68C59CF contains an EC public key using curve SECP_256_R_1
>
> The full certificate is:

<details>
    <summary>{ "tbsCertificate": {…</summary>

```json
{
  "tbsCertificate": {
    "serialNumber": "GYIe3KaMWc8=",
    "signatureAlgorithm": "ES384",
    "issuerName": [
      {
        "type": "C",
        "value": "13024154"
      },
      {
        "type": "O",
        "value": "133352657075626C696B204F65737465727265696368202876657274726574656E20647572636820424B4120756E6420424D445729"
      },
      {
        "type": "OU",
        "value": "130A542D556D676562756E67"
      },
      {
        "type": "CN",
        "value": "132B542D52657075626C696B2D4F657374657272656963682D41757468656E746966697A696572756E672D3031"
      }
    ],
    "validFrom": "170D3233303932303132343135305A",
    "validUntil": "170D3233303932333132353134395A",
    "subjectName": [
      {
        "type": "C",
        "value": "13024154"
      },
      {
        "type": "O",
        "value": "133352657075626C696B204F65737465727265696368202876657274726574656E20647572636820424B4120756E6420424D445729"
      },
      {
        "type": "OU",
        "value": "130A542D556D676562756E67"
      },
      {
        "type": "CN",
        "value": "1340542D42696E64756E67732D5A6572746966696B61742D4157502D3165306436383063656464613439636539313337386462613934326533663432346663663164"
      }
    ],
    "publicKey": {
      "type": "EC",
      "curve": "P-256",
      "x": "/wlkNNLhIKmO7tQY1824tD6FSf1/evXzQui1quzsSpw=",
      "y": "SggoS/B464PKcHXT9phYxBPOnMEwL/ZC+Q9vZXoxY/g="
    },
    "extensions": [
      {
        "id": "1.3.6.1.5.5.7.1.1",
        "value": "MDEwLwYIKwYBBQUHMAGGI2h0dHA6Ly9vY3NwMy5vZXN0ZXJyZWljaC5ndi5hdC9vY3Nw"
      },
      {
        "id": "2.5.29.14",
        "value": "BBRQQnap5sOMkNX+lCHhWGstLkEe6Q=="
      },
      {
        "id": "2.5.29.35",
        "value": "MBaAFAgwoHa6fUvtsBT+jMHkTBAnomXU"
      },
      {
        "id": "2.5.29.31",
        "value": "MDQwMqAwoC6GLGh0dHA6Ly9jcmwzLm9lc3RlcnJlaWNoLmd2LmF0L2NybC9vZWd2LzFhY2Ex"
      },
      {
        "id": "2.5.29.15",
        "critical": true,
        "value": "AwIHgA=="
      },
      {
        "id": "2.5.29.37",
        "critical": true,
        "value": "MAoGCCsGAQUFBwMC"
      },
      {
        "id": "1.2.40.0.10.2.6.1.1",
        "value": "MA2gAwIBAIEGcmVhZGVy"
      }
    ]
  },
  "signatureAlgorithm": "ES384",
  "signature": "MGQCMEAqUL8qRpPwDi7u1qeEXfJp7Pk4GE4diI9GTSTE/yzFEHJD/o6SRy+lCbJgo58+AwIwCTsMgGdWLIMkN9n1KsuLt6jD/FFF1qzHuj5cTH4JeY0bNwLPxvAUVk3V43pCfMgD"
}
```

</details> 

> Re-encoding it produces the same bytes? true

### Creating a CSR

```kotlin
val ecPublicKey: ECPublicKey = TODO("From platform-specific code")
val cryptoPublicKey = CryptoPublicKey.EC.fromJcaPublicKey(ecPublicKey).getOrThrow()

val commonName = "DefaultCryptoService"
val signatureAlgorithm = X509SignatureAlgorithm.ES256


val tbsCsr = TbsCertificationRequest(
    version = 0,
    subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
    publicKey = cryptoPublicKey
)
val signed: ByteArray = TODO("pass tbsCsr.encodeToDer() to platform code")
val csr = Pkcs10CertificationRequest(tbsCsr, signatureAlgorithm, signed)

println(csr.encodeToDer())
```

Which results in the following output:

> [3081D9308181020100301F311D301B06035504030C1444656661756C74437279
> 70746F536572766963653059301306072A8648CE3D020106082A8648CE3D0301
> 07034200043797E977E359AAABFC9177E7C95FD5B4BE4AC24C4FF13F3233F774
> E8B65FE5FBA5057513BD076CFFB2E17567AC9BD43737FB6BDF496CC6DCB47194
> BBE7512F0BA000300A06082A8648CE3D0403020347003044022079D188C09E20
> C70AFF096B9484DDDE70484485FD551676273A517E818B94644E02206B222905
> D343C1D6FC9319A364CECA7E67956E4B99D63537E17A9F5D4093D7AE](https://lapo.it/asn1js/#MIHZMIGBAgEAMB8xHTAbBgNVBAMMFERlZmF1bHRDcnlwdG9TZXJ2aWNlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEN5fpd-NZqqv8kXfnyV_VtL5KwkxP8T8yM_d06LZf5fulBXUTvQds_7LhdWesm9Q3N_tr30lsxty0cZS751EvC6AAMAoGCCqGSM49BAMCA0cAMEQCIHnRiMCeIMcK_wlrlITd3nBIRIX9VRZ2JzpRfoGLlGROAiBrIikF00PB1vyTGaNkzsp-Z5VuS5nWNTfhep9dQJPXrg)

### Working with Generic ASN.1 Structures

The magic shown above is based on a from-scratch 100% KMP implementation of an ASN.1 encoder and parser.
To parse any DER-encoded ASN.1 structure, call either:

* `Asn1Element.parse()`, which will consume all bytes and return the first parsed ASN.1 element.
This method throws if parsing errors occur or any trailing bytes are left after parsing the first element.
* `Asn1Element.parseFirst()`, which will try to parse a single toplevel ASN.1 element.
Any remaining bytes can still be consumed from the iterator, as it will only be advanced to right after the first parsed element.
* `Asn1Element.parseAll()`, wich consumes all bytes, parses all toplevel ASN.1 elements, and returns them as list.
Throws on any parsing error.

`Asn1Element`s can encoded by accessing the lazily evaluated `.derEncoded` property.
Even for parsed elements, this is a true re-encoding. The original bytes are discarded after decoding.

**Note that decoding operations will throw exceptions if invalid data is provided!**

A parsed `Asn1Element` can either be a primitive (whose tag and value can be read) or a structure (like a set or
sequence) whose child nodes can be processed as desired. Subclasses of `Asn1Element` reflect this:

* `Asn1Primitive`
  * `Asn1BitString` (for convenience)
  * `Asn1PrimitiveOctetString` (for convenience)
* `Asn1Structure`
    * `Asn1Sequence` and `Asn1SequenceOf`
    * `Asn1Set` and `Asn1SetOf` (sorting children by default)
    * `Asn1EncapsulatingOctetString` (tagged as OCTET STRING, containing a valid ASN.1 structure or primitive)
    * `Asn1ExplicitlyTagged` (user-specified tag + CONTEXT_SPECIFIC + CONSTRUCTED)
    * `Asn1CustomStructure` (any other CONSTRUCTED tag not fitting the above options. CONSTRUCTED bit may be overridden)

Convenience wrappers exist, to cast to any subtype (e.g. `.asSequence()`). These shorthand functions throw an `Asn1Exception`
if a cast is not possible.  
Any complex data structure (such as CSR, public key, certificate, …) implements `Asn1Encodable`, which means you can:

* encapsulate it into an ASN.1 Tree by calling `.encodeToTlv()`
* directly get a DER-encoded byte array through the `.encodetoDer()` function

A tandem of helper functions is available for primitives (numbers, booleans, string, bigints):

* `encodeToAsn1Primitive` to produce an `Asn1Primitive` that can directly be DER-encoded
* `encodeToAsn1ContentBytes` to produce the content bytes of a TLV primitive (the _V_ in TLV)

Variations of these exist for `Instant` and `ByteArray`.

Check out [Asn1Encoding.kt](indispensable/src/commonMain/kotlin/at/asitplus/signum/indispensable/asn1/encoding/Asn1Encoding.kt) for a full
list of helper functions.

#### Decoding Values

Various helper functions exist to facilitate decoding the values contained in `Asn1Primitives`, such as `readInt()`,
for example. To also support decoding more complex structures, the companion objects of complex classes (such as certificates, CSRs, …)
implement `Asn1Decodable`, which allows for:

* directly parsing DER-encoded byte arrays by calling `.decodeFromDer(bytes)` and `.decodeFromDerHexString`
* processing an `Asn1Element` by calling `.decodefromTlv(src)`

Both encoding and decoding functions come in two _safe_ (i.e. non-throwing) variants:
* `…Safe()` which returns a [KmmResult](https://github.com/a-sit-plus/kmmresult)
* `…orNull()` which returns null on error

Similarly to encoding, a tandem of decoding functions exists for primitives:
* `decodeToXXX` to be invoked on an `Asn1Primitive` to decode a DER-encoded primitive into the target type
* `decodeFromAsn1ContentBytes` to be invoked on the companion of the target type to decode the content bytes of a TLV primitive (the _V_ in TLV)

However, anything can be decoded and tagged at will. Therefore, a generic decoding function exists, which has the
following signature:

```kotlin
inline fun <reified T> Asn1Primitive.decode(assertTag: Asn1Element.Tag, decode: (content: ByteArray) -> T) 
```

Check out [Asn1Decoding.kt](indispensable/src/commonMain/kotlin/at/asitplus/signum/indispensable/asn1/encoding/Asn1Decoding.kt) for a full
list of helper functions.

#### ASN1 DSL for Creating ASN.1 Structures

While it is perfectly possible to manually construct a hierarchy of `Asn1Element` objects, we provide a more convenient
DSL, which returns an `Asn1Structure`:

```kotlin
Asn1.Sequence {
  +ExplicitlyTagged(1uL) {
    +Asn1Primitive(Asn1Element.Tag.BOOL, byteArrayOf(0x00)) //or +Asn1.Bool(false)
  }
  +Asn1.Set {
    +Asn1.Sequence {
      +Asn1.SetOf {
        +PrintableString("World")
        +PrintableString("Hello")
      }
      +Asn1.Set {
        +PrintableString("World")
        +PrintableString("Hello")
        +Utf8String("!!!")
      }

    }
  }
  +Asn1.Null()

  +ObjectIdentifier("1.2.603.624.97")

  +(Utf8String("Foo") withImplicitTag (0xCAFEuL withClass TagClass.PRIVATE))
  +PrintableString("Bar")

  //fake Primitive
  +(Asn1.Sequence { +Asn1.Int(42) } withImplicitTag (0x5EUL without CONSTRUCTED))

  +Asn1.Set {
    +Asn1.Int(3)
    +Asn1.Int(-65789876543L)
    +Asn1.Bool(false)
    +Asn1.Bool(true)
  }
  +Asn1.Sequence {
    +Asn1.Null()
    +Asn1String.Numeric("12345")
    +UtcTime(Clock.System.now())
  }
} withImplicitTag (1337uL withClass TagClass.APPLICATION)
```

In accordance with DER-Encoding, this produces the following ASN.1 structure:

```
Application 1337 (9 elem)

    [1] (1 elem)
        BOOLEAN false
    SET (1 elem)
        SEQUENCE (2 elem)
            SET (2 elem)
                PrintableString World
                PrintableString Hello
            SET (3 elem)
                UTF8String !!!
                PrintableString World
                PrintableString Hello
    NULL
    OBJECT IDENTIFIER 1.2.603.624.97
    Private 51966 (3 byte) Foo
    PrintableString Bar
    [94] (3 byte) 02012A
    SET (4 elem)
        BOOLEAN false
        BOOLEAN true
        INTEGER 3
        INTEGER (36 bit) -65789876543
    SEQUENCE (3 elem)
        NULL
        NumericString 12345
        UTCTime 2024-09-16 11:53:51 UTC
```

## Limitations

* Multiplatform signature verification **only** based on platform verifiers (and a fallback 100% KMP verifier) ist included as a prerelease. signature creation is on its way.
* While the ASN.1 parser will happily parse any valid **DER-encoded** ASN.1 structure you throw at it and the encoder will
  write it back correctly too. (No, we don't care for BER, since we want to transport cryptographic material!)
* Higher-level abstractions (such as `X509Certificate`) are too lenient in some aspects and
  too strict in others.
  For example: DSA-signed certificates will not parse to an instance of `X509Certificate`.
  At the same time, certificates containing the same extension multiple times will work fine, even though they violate
  the spec.
  This is irrelevant in practice, since platform-specific code will perform the actual cryptographic operations on these
  data structures and complain anyway, if something is off.
* No OCSP and CRL Checks (though it is perfectly possible to parse this data from a certificate and implement the checks)
* We do need more comprehensive tests, but we're getting there, mostly thanks to [@iaik-jheher](https://github.com/iaik-jheher)
  and [@n0900](https://github.com/n0900).
* Number of supported Algorithms is limited to the usual suspects (sorry, no Bernstein curves )-:)



## Contributing
External contributions are greatly appreciated! Be sure to observe the contribution guidelines (see [CONTRIBUTING.md](CONTRIBUTING.md)).
In particular, external contributions to this project are subject to the A-SIT Plus Contributor License Agreement (see also [CONTRIBUTING.md](CONTRIBUTING.md)).


---

| ![eu.svg](docs/docs/assets/eu.svg) <br> Co&#8209;Funded&nbsp;by&nbsp;the<br>European&nbsp;Union |   This project has received funding from the European Union’s <a href="https://digital-strategy.ec.europa.eu/en/activities/digital-programme">Digital Europe Programme (DIGITAL)</a>, Project 101102655 — POTENTIAL.   |
|:-----------------------------------------------------------------------------------------------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|


---

<p align="center">
The Apache License does not apply to the logos, (including the A-SIT logo) and the project/module name(s), as these are the sole property of
A-SIT/A-SIT Plus GmbH and may not be used in derivative works without explicit permission!
</p>

