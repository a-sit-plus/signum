![Signum](assets/signum-dark-large.png#only-light)
![Signum](assets/signum-light-large.png#only-dark)

[![Kotlin](https://img.shields.io/badge/kotlin-multiplatform-orange.svg?logo=kotlin)](http://kotlinlang.org)
[![Kotlin](https://img.shields.io/badge/kotlin-2.1.20-blue.svg?logo=kotlin)](http://kotlinlang.org)
[![Java](https://img.shields.io/badge/java-17+-blue.svg?logo=OPENJDK)](https://www.oracle.com/java/technologies/downloads/#java11)
[![Android](https://img.shields.io/badge/Android-SDK--30-37AA55?logo=android)](https://developer.android.com/tools/releases/platforms#11)
[![Maven Central (indispensable)](https://img.shields.io/maven-central/v/at.asitplus.signum/indispensable?label=maven-central%20%28indispensable%29)](https://mvnrepository.com/artifact/at.asitplus.signum/)
[![Maven Central (Supreme)](https://img.shields.io/maven-central/v/at.asitplus.signum/supreme?label=maven-central%20%28Supreme%29)](https://mvnrepository.com/artifact/at.asitplus.signum/supreme)

# Signum – Kotlin Multiplatform Crypto/PKI Library and ASN1 Parser + Encoder


This [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library provides platform-independent data
types and platform-native functionality related to crypto and PKI applications:

* **Multiplatform, platform-native crypto** &rarr; Check out the included [CMP demo App](app.md) to see it in
  action!
    * **ECDSA and RSA Signer and Verifier**
    * **Multiplatform ECDH key agreement**
    * **Hardware-Backed crypto on Android and iOS**
    * **Platform-native attestation on iOS and Android**
    * **Configurable biometric authentication on Android and iOS without callbacks or activity passing** (✨Magic!✨)
    * **Multiplatform AES**
    * **Multiplatform HMAC**
* Public Keys (RSA and EC)
* Private Keys (RSA and EC)
* Algorithm Identifiers (Signatures, Hashing)
* X509 Certificate Class (create, encode, decode)
* Certification Request (CSR)
* ObjectIdentifier Class with human-readable notation (e.g. 1.2.9.6245.3.72.13.4.7.6)
* Generic ASN.1 abstractions to operate on and create arbitrary ASN.1 Data
* JOSE-related data structures (JSON Web Keys, JWT, etc…)
* COSE-related data structures (COSE Keys, CWT, etc…)
* 100% pure Kotlin BitSet
* Exposes Multibase Encoder/Decoder as an API dependency
  including [Matthew Nelson's smashing Base16, Base32, and Base64 encoders](https://github.com/05nelsonm/encoding)
* **ASN.1 Parser and Encoder including a DSL to generate ASN.1 structures**
    * Parse, create, explore certificates, public keys, CSRs, and **arbitrary ASN.1* structures* on all supported platforms
    * Powerful, expressive, type-safe ASN.1 DSL on all KMP targets!
    * Parse, create, explore certificates, public keys, CSRs, and **arbitrary ASN.1* structures* on all supported platforms

This last bit means that you can share ASN.1-related logic across platforms.
The very first bit means that you can create and verify signatures on the JVM, Android and on iOS, using platform-native
crypto hardware.
**We also provide comprehensive API docs [here](dokka/index.html)**!

## Using it in your Projects

This library was built for [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html). Currently, it targets
the JVM, Android and iOS.

This library consists of four modules, each of which is published on maven central:

|                                                       Name                                                        | Info                                                                                                                                                                                                                                                               |
|:-----------------------------------------------------------------------------------------------------------------:|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|   ![indispensable-asn1](assets/asn1-dark.png#only-light) ![indispensable-asn1](assets/asn1-light.png#only-dark)   | **Indispensable ASN.1** module containing the most sophisticated KMP ASN.1 engine in the known universe. kotlinx-* dependencies aside, it only depends only on [KmmResult](https://github.com/a-sit-plus/kmmresult) for extra-smooth iOS interop.                  | 
|        ![indispensable](assets/core-dark.png#only-light) ![indispensable](assets/core-light.png#only-dark)        | **Indispensable** base module containing the cryptographic data structures, algorithm identifiers, X.509 certificate, …. Depends on the ASN.1 engine.                                                                                                              | 
| ![indispensable-josef](assets/josef-dark.png#only-light) ![indispensable-josef](assets/josef-light.png#only-dark) | **Indispensable Josef** JOSE add-on module containing JWS/E/T-specific data structures and extensions to convert from/to types contained in the base module. Includes all required kotlinx-serialization magic to allow for spec-compliant de-/serialization.      | 
| ![indispensable-cosef](assets/cosef-dark.png#only-light) ![indispensable-cosef](assets/cosef-light.png#only-dark) | **Indispensable Cosef** COSE add-on module containing all COSE/CWT-specific data structures and extensions to convert from/to types contained in the base module. Includes all required kotlinx-serialization magic to allow for spec-compliant de-/serialization. |
|           ![Supreme](assets/supreme-dark.png#only-light) ![Supreme](assets/supreme-light.png#only-dark)           | **Supreme** KMP crypto provider implementing hardware-backed signature creation and verification across mobile platforms (Android KeyStore / iOS Secure Enclave) and JCA compatibility (on the JVM).                                                               | 

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
implementation("at.asitplus.signum:supreme:$supreme_version")
```


## Rationale
Looking for a KMP cryptography framework, you have undoubtedly come across
[cryptography-kotlin](https://github.com/whyoleg/cryptography-kotlin). So have we and it is a powerful
library, supporting more platforms and more cryptographic operations than Signum Supreme.
This begs the question: Why implement another, incompatible
cryptography framework from scratch? The short answer is: Signum and cryptography-kotlin pursue different goals and priorities.

!!! tip inline end
    A feature comparison between Signum and cryptography-kotlin is part of the [feature matrix](features.md#signum-vs-cryptography-kotlin).

cryptography-kotlin strives for covering a wide range of targets and a broad range of operations based on a flexible provider architecture.
Signum, on the other hand, focuses on tight platform integration (**including hardware-backed crypto and attestation!**),
and comprehensive ASN.1, JOSE, and COSE support.

??? info "More…"
    Signum was born from the need to have cryptographic data structures available across platforms, such as public keys, signatures,
    certificates, CSRs, as well as COSE and JOSE data. Hence, we needed a fully-featured ASN.1 engine and mappings from
    X.509 to COSE and JOSE datatypes. We required comprehensive ASN.1 introspection and builder capabilities across platforms.
    Most notably, Apple has been notoriously lacking anything even remotely usable
    and [SwiftASN1](https://github.com/apple/swift-asn1) was out of the question for a couple of reasons.
    Most notably, it did not exist when we started work on Signum. Hence, there was **neither ASN.1 parser, nor encoder on Apple platforms**
    that was actually usable. In effect: there was no KMP ASN.1 codec in sight, much less a type-safe, user-friendly one.
    As it stands now, our ASN.1 engine can handle almost anything you throw at it, in some areas even exceeding Bouncy Castle!
    cryptography-kotlin only added basic ASN.1 capabilities over a year after Signum's development started.
    <br>
    We are also unaware of any other library offering comprehensive JOSE and COSE data structures based on kotlinx-serialization.
    Hence, we implemented those ourselves, with first-class interop to our generic cryptographic data structures.
    We also support platform-native interop meaning that you can easily convert a Json Web Key to a JCA key or even a `SecKeyRef` on iOS.
    
    Having actual implementations of cryptographic operations available was only second on our list of priorities. From the
    get-go, it was clear that we wanted the tightest possible platform integration on Android and iOS, including hardware-backed
    storage of key material and in-hardware execution of cryptographic operations whenever possible.
    We also needed platform-native attestation capabilities (and so will you sooner or later, if you are doing anything
    mission-critical on mobile targets!).
    While this approach does limit the number of available cryptographic operations, it also means that all cryptographic operations
    involving secrets (e.g. private keys) provide the same security guarantees as platform-native implementations do &mdash;
    **because they are the same** under the hood. Most notably: **hardware-backed private keys
    never even leave the hardware crypto modules**!<br>
    This tight integration and our focus on mobile comes at the cost of the **Supreme KMP crypto provider only supporting JVM,
    Android, and iOS**.
    
    cryptography-kotlin, on the other hand allows you to perform a wider range of cryptographic functions an all KMP targets,
    Most prominently, it already supports RSA encryption, key stretching, and key derivation, which Signum currently lacks.
    On the other hand, cryptography-kotlin currently offers neither hardware-backed crypto, nor attestation capabilities.



## Demo Reel

This section provides a quick overview to show how this library works.
Since this is only a peek. more detailed information can be found in the corresponding sections dedicated to individual
features.

### Signature Creation (Supreme)

To create a signature, obtain a `Signer` instance.
You can do this using `Signer.Ephemeral` to create a signer for a throwaway keypair:

```kotlin
val signer = Signer.Ephemeral {}.getOrThrow()
val plaintext = "You have this.".encodeToByteArray()
val signature = signer.sign(plaintext).signature
println("Signed using ${signer.signatureAlgorithm}: $signature")
```

If you want to create multiple signatures using the same ephemeral key, you can obtain an `EphemeralKey` instance, then
create signers from it:

```kotlin
val key = EphemeralKey { rsa {} }.getOrThrow()
val sha256Signer = key.getSigner { rsa { digest = Digests.SHA256 } }.getOrThrow()
val sha384Signer = key.getSigner { rsa { digest = Digests.SHA384 } }.getOrThrow()
```

The instances can be configured using the configuration DSL.
Any unspecified parameters use sensible, secure defaults.

### Signature Verification (Supreme)

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

### Symmetric Encryption (Supreme)
We currently support AES-CBC, AES-GCM, and a very flexible flavour of AES-CBC-HMAC.
This is supported across all _Supreme_ targets and works as follows:
```kotlin
val payload = "More matter, with less Art!".encodeToByteArray()

//define parameters
val algorithm = SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_512
val secretKey = algorithm.randomKey()
val macKey = algorithm.randomKey()
val aad = Clock.System.now().toString().encodeToByteArray()

val ciphertext =
    //You typically chain encryptorFor and encrypt
    //because you should never re-use an IV
    algorithm.encryptorFor(
        secretKey = secretKey,
        dedicatedMacKey = macKey,
        aad = aad
    ).getOrThrow(/*TODO Error handling*/)
        .encrypt(payload).getOrThrow(/*TODO Error Handling*/)
val recovered = ciphertext.decrypt(secretKey, macKey)
    .getOrThrow(/*TODO Error handling*/)

recovered shouldBe payload //success!
```

### ASN.1 Parsing and Encoding

Relevant classes like `CryptoPublicKey`, `X509Certificate`, `Pkcs10CertificationRequest`, etc. all
implement `Asn1Encodable` and their respective companions implement `Asn1Decodable`.
Which means that you can do things like parsing and examining certificates, creating CSRs, or transferring key
material.
Parsing and re-encoding an X.509 certificate works as follows:

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

println("Re-encoding it produces the same bytes? ${cert.encodeToDer() contentEquals certBytes}")
```

Which produces the following output:

     Certificate with serial no. 19821EDCA68C59CF contains an EC public key using curve SECP_256_R_1
     Re-encoding it produces the same bytes? true

### ASN.1 Builder DSL

While predefined structures are essential for working with cryptographic material in a PKI context,
full control is sometimes required.
Signum directly support this with an ASN.1 builder DSL, including explicit and implicit tagging:

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

                                                            // ↓ faux primitive ↓
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

This produces the following ASN.1 structure:

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

### COSE and JOSE

The modules _Indispensable Josef_ and _Indispensable Cosef_ provide data structures to work within JOSE and COSE
domains, respectively.
Since these are essentially data classes, there's really not much magic to using them.
The main reason those modules exist, is to keep the core _Indispensable_ module small, so it can be used without pulling
in unnecessary functionality.
COSE and JOSE data types come with mapping functionality to core (_Indispensable_) data types,
such as `CryptoPublicKey` and are guaranteed to parse and serialize correctly.

#### COSE Parsing (Indidpensable Cosef)
As a quick self-contained example, deserializing the following `CoseSigned` structure works as expected:
```kotlin
val input = "d28443a10126a10442313154546869732069732074686520636f6e74656e" +
                "742e58408eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a" +
                "91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b09" +
                "16e5a4c345cacb36"
val cose = CoseSigned.deserialize(input.uppercase().decodeToByteArray(Base16Strict))
    .also { println(it.getOrNull()) }
```

The output confirms that parsing was successful:

    CoseSigned(protectedHeader=CoseHeader(algorithm=ES256, criticalHeaders=null, contentType=null, kid=null, iv=null, partialIv=null, coseKey=null, certificateChain=null), unprotectedHeader=CoseHeader(algorithm=null, criticalHeaders=null, contentType=null, kid=3131, iv=null, partialIv=null, coseKey=null, certificateChain=null), payload=546869732069732074686520636F6E74656E742E, signature=8EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF0B0117E2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36)

#### JWK creation (Indispensable Josef)
JsonWebKeys can be manually created (just as COSE keys) and converted to `CryptoPublicKey`, so we can pass it to a _Supreme_ verifier:

```kotlin
val parsedN = ("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2" +
        "aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi" +
        "FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65Y" +
        "GjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n" +
        "91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_x" +
        "BniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw").decodeToByteArray(Base64UrlStrict)
val parsedE = "AQAB".decodeToByteArray(Base64UrlStrict)
val key = JsonWebKey(type = JwkType.RSA, n = parsedN, e = parsedE)

key.jwkThumbprint //this is "urn:ietf:params:oauth:jwk-thumbprint:sha256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
key.toCryptoPublicKey().getOrThrow() //<- this we can pass to a Supreme verifier
```

## Further Reading
Every module has dedicated documentation pages, and we provide full API docs.
Also checkout the feature matrix to get an overview of what is and isn't supported.

---

<div class="inline euflag" markdown>
   ![eu.svg](assets/eu.svg)
  <br> Co&#8209;Funded&nbsp;by&nbsp;the<br>European&nbsp;Union
</div>
<div class="valign">
<p>
This project has received funding from the European Union’s <a href="https://digital-strategy.ec.europa.eu/en/activities/digital-programme">Digital Europe Programme (DIGITAL)</a>, Project 101102655 — POTENTIAL.
</p>
</div>
