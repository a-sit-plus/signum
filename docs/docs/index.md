![Signum](assets/signum-dark-large.png#only-light)
![Signum](assets/signum-light-large.png#only-dark)

<p align= "center" markdown>

[![A-SIT Plus Official](https://raw.githubusercontent.com/a-sit-plus/a-sit-plus.github.io/709e802b3e00cb57916cbb254ca5e1a5756ad2a8/A-SIT%20Plus_%20official_opt.svg)](https://plus.a-sit.at/open-source.html)
[![Kotlin](https://img.shields.io/badge/kotlin-multiplatform-orange.svg?logo=kotlin)](http://kotlinlang.org)
[![Kotlin](https://img.shields.io/badge/kotlin-2.4.0-blue.svg?logo=kotlin)](http://kotlinlang.org)
[![Java](https://img.shields.io/badge/java-17+-blue.svg?logo=OPENJDK)](https://www.oracle.com/java/technologies/downloads/#java11)
[![iOS](https://img.shields.io/badge/iOS-15-white?logo=apple)](https://support.apple.com/en-gb/108051)

</p>

| [![Android](https://img.shields.io/badge/Android_(indispensable)-SDK--26-37AA55?logo=android)](https://developer.android.com/tools/releases/platforms#8.0) |  [![Maven Central (indispensable)](https://img.shields.io/maven-central/v/at.asitplus.signum/indispensable?label=maven-central%20%28indispensable%29)](https://mvnrepository.com/artifact/at.asitplus.signum/)  |  [![Maven SNAPSHOT (indispensable)](https://img.shields.io/nexus/snapshots/https/s01.oss.sonatype.org/at.asitplus.signum/indispensable?label=SNAPSHOT%20%28indispensable%29)](https://s01.oss.sonatype.org/content/repositories/snapshots/at/asitplus/signum/indispensable/)  |
|:----------------------------------------------------------------------------------------------------------------------------------------------------------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
|    [![Android](https://img.shields.io/badge/Android_(Supreme)-SDK--30-37AA55?logo=android)](https://developer.android.com/tools/releases/platforms#11)     |       [![Maven Central (Supreme)](https://img.shields.io/maven-central/v/at.asitplus.signum/supreme?label=maven-central%20%28Supreme%29)](https://mvnrepository.com/artifact/at.asitplus.signum/supreme)        |              [![Maven SNAPSHOT (Supreme)](https://img.shields.io/nexus/snapshots/https/s01.oss.sonatype.org/at.asitplus.signum/supreme?label=SNAPSHOT%20%28Supreme%29)](https://s01.oss.sonatype.org/content/repositories/snapshots/at/asitplus/signum/supreme/)              |


# Signum – Kotlin Multiplatform Crypto/PKI Library

This [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library provides platform-independent data
types and platform-native functionality related to crypto and PKI applications:

* **Multiplatform, platform-native crypto** &rarr; Check out the included [CMP demo App](app.md) to see it in action!
    * **ECDSA and RSA Signer and Verifier**
    * **Multiplatform ECDH key agreement**
    * **Hardware-Backed crypto on Android and iOS**
    * **Platform-native attestation on iOS and Android**
    * **Configurable biometric authentication on Android and iOS without callbacks or activity passing** (✨Magic!✨)
    * **Multiplatform AES and ChaCha20-Poly1305**
    * **Multiplatform HMAC and RSA Encryption**
* **Multiplatform KDF** (using platform-native hashing): PBKDF2, HKDF, and scrypt
* Public and Private Keys (RSA and EC)
* Algorithm Identifiers (Signatures, Hashing)
* Certificate and Certification Request (CSR) classes
* **PKIX certificate path construction and validation**, including typed extensions and names
* **[Hybrid Public Key Encryption (HPKE)](supreme.md#hybrid-public-key-encryption)**
* JOSE-related data structures (JSON Web Keys, JWT, etc…)
* COSE-related data structures (COSE Keys, CWT, etc…)
* Exposes Multibase Encoder/Decoder as an API dependency
  including [Matthew Nelson's smashing Base16, Base32, and Base64 encoders](https://github.com/05nelsonm/encoding)

The ASN.1 engine has become its own library, [awesn1](https://a-sit-plus.github.io/awesn1/).
Signum builds its key, certificate, and CSR serialization on top of it; arbitrary ASN.1 structures and the builder DSL
are documented over there. Which means that you can still share your cryptographic data structures across platforms,
while using the engine independently of Signum.

**We also provide comprehensive API docs [here](dokka/index.html)**!

## Using it in your Projects

The data modules support a broad range of KMP targets. The _Supreme_ crypto provider targets the JVM, Android, and iOS.
The [feature matrix](features.md) describes operations and platform restrictions.

This library consists of six public modules:

| Name | Info |
|:-----|:-----|
| **[Indispensable](indispensable.md)** | Base module containing cryptographic data structures, open algorithm interfaces, keys, certificates and CSRs. Uses awesn1 for serialization. |
| **[Indispensable Josef](indispensable-josef.md)** | JOSE add-on module containing JWS/E/T-specific data structures and extensions to convert from/to core types. Includes the required kotlinx.serialization magic. |
| **[Indispensable Cosef](indispensable-cosef.md)** | COSE add-on module containing COSE/CWT-specific data structures and extensions to convert from/to core types. Includes the required kotlinx.serialization magic. |
| **[Indispensable PKIX](indispensable-pkix.md)** | Typed certificate extensions, X.500 and general names, trust-anchor data and a bundled trust store. |
| **[Supreme](supreme.md)** | KMP crypto provider implementing platform-native operations and hardware-backed signing on mobile platforms. |
| **[PKIX Supreme](pkix-supreme.md)** | Certificate path construction and validation, with access to platform trust stores. |

This separation keeps dependencies to a minimum, i.e. it enables including only JOSE-related functionality, if COSE is irrelevant.
More importantly, it allows for processing cryptographic material without imposing the inclusion of a crypto provider.

Simply declare the desired dependency to get going. For this release, the coordinates are:

| Module | Dependency |
|:-------|:-----------|
| Indispensable | `at.asitplus.signum:indispensable:4.0.0` |
| Josef | `at.asitplus.signum:indispensable-josef:4.0.0` |
| Cosef | `at.asitplus.signum:indispensable-cosef:4.0.0` |
| PKIX data | `at.asitplus.signum:indispensable-pkix:4.0.0` |
| Supreme | `at.asitplus.signum:supreme:1.0.0` |
| PKIX operations | `at.asitplus.signum:pkix-supreme:1.0.0` |

!!! tip
    Already using Signum 3.x? Start with the [migration guide](migration.md).
    This is a major refactor, including the awesn1 extraction and extensibility throughout the library.

### Modulator

Signum uses the [Modulator Gradle plugin](https://github.com/a-sit-plus/modulator) for optional integration modules.
For example, `pkix-supreme` connects Supreme's operations with Indispensable PKIX's data types.
With `at.asitplus.gradle.modulator` (currently **0.1.0**) applied to a consuming KMP subproject, declaring
Supreme 1.0.0 and Indispensable PKIX 4.0.0 in the same `api` or `implementation` scope also pulls in PKIX Supreme.
You can also declare PKIX Supreme explicitly, as shown above. See the [migration guide](migration.md#modulator-and-bridge-dependencies)
for the dependency selection details. Dependency selection does not replace `Signum.installPkix()` during startup.

## Rationale

Looking for a KMP cryptography framework, you have undoubtedly come across
[cryptography-kotlin](https://github.com/whyoleg/cryptography-kotlin). So have we and it is a powerful library.
This begs the question: Why implement another, incompatible cryptography framework from scratch?
The short answer is: Signum and cryptography-kotlin pursue different goals and priorities.
Signum focuses on tight platform integration (**including hardware-backed crypto and attestation!**),
and comprehensive PKI, JOSE, and COSE support.

??? info "More…"
    Signum was born from the need to have cryptographic data structures available across platforms, such as public keys, signatures,
    certificates, CSRs, as well as COSE and JOSE data. Hence, we needed an ASN.1 engine and mappings from
    X.509 to COSE and JOSE datatypes. That engine is now [awesn1](https://a-sit-plus.github.io/awesn1/).
    The two libraries can evolve independently, while Signum keeps its first-class interop between cryptographic data structures.
    We also support platform-native interop meaning that you can easily convert a JSON Web Key to a JCA key or even a `SecKeyRef` on iOS.

    Having actual implementations of cryptographic operations available was only second on our list of priorities. From the
    get-go, it was clear that we wanted the tightest possible platform integration on Android and iOS, including hardware-backed
    storage of key material and in-hardware execution of cryptographic operations whenever possible.
    We also needed platform-native attestation capabilities.
    Most notably: **hardware-backed private keys never even leave the hardware crypto modules**!
    This tight integration and our focus on mobile comes at the cost of the **Supreme KMP crypto provider only supporting JVM,
    Android, and iOS**.

    External libraries can now extend the algorithms, implementations, format mappings, and configuration DSL.
    Refer to [Extensibility](extensibility.md) for the process; the built-in algorithms remain available with sensible defaults.

## Demo Reel

This section provides a quick overview to show how this library works.
Since this is only a peek, more detailed information can be found in the corresponding sections dedicated to individual features.
The snippets below are taken straight from the JVM tests. This manual's platform-specific Kotlin examples live in the corresponding Android and iOS test sources.

### Signature Creation (Supreme)

To create a signature, obtain a `Signer` instance.
You can do this using `Signer.Ephemeral` to create a signer for a throwaway keypair:

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-ephemeral"
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-signing"
```

1. Signing returns a `SignatureResult`; reading `signature` throws if signing was cancelled. Unexpected failures propagate as exceptions.

The instance can be configured using the configuration DSL.
Any unspecified parameters use sensible, secure defaults. Keep the signer around to sign more than one message.

### Signature Verification (Supreme)

To verify a signature, obtain a `SignatureVerifier` using `verifierFor`, passing a trusted public key.
A successful verification returns `SignatureVerifier.Success`; an invalid signature throws.

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-verification"
```

1. The test also checks that a different message cannot be verified using the same signature.

### Symmetric Encryption (Supreme)

We support AES and ChaCha20-Poly1305, including a flexible flavour of AES-CBC-HMAC.
Here is how to encrypt and recover a message:

```kotlin
--8<-- "supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/SupremeExamples.kt:supreme-symmetric"
```

1. This API returns `KmmResult`. Check the result before using the sealed box.

### Key Serialization (Indispensable)

Relevant classes like `CryptoPublicKey`, `Certificate`, and `CertificationRequest` implement `Encodable`;
their companions implement `Decodable`. Signum's contextual serializers bridge those semantic types to awesn1 models.
Use `Signum.Der` so configuration and registered extensions are shared by all public helpers:

```kotlin
--8<-- "indispensable/src/jvmTest/kotlin/at/asitplus/signum/examples/CoreExamples.kt:core-key-roundtrip"
```

1. `Signum.Der` uses the registered contextual serializer when decoding the public key.

The [Indispensable manual](indispensable.md) describes the format representations and PEM helpers.
For the ASN.1 parser, codec, and builder DSL, check out [awesn1](https://a-sit-plus.github.io/awesn1/).

### COSE and JOSE

The modules _Indispensable Josef_ and _Indispensable Cosef_ provide data structures to work within JOSE and COSE
 domains, respectively. Since these are essentially data classes, there's really not much magic to using them.
The main reason those modules exist, is to keep the core _Indispensable_ module small, so it can be used without pulling
in unnecessary functionality.

#### COSE Signing (Indispensable Cosef)

COSE data types map to core types such as `CryptoPublicKey` and `CryptoSignature`:

```kotlin
--8<-- "indispensable-cosef/src/jvmTest/kotlin/at/asitplus/signum/examples/CoseExamples.kt:cose-sign-verify"
```

1. The verification key comes from our independently trusted signer. Applications must supply their own trusted key.

#### JWK Creation (Indispensable Josef)

JSON Web Keys can be converted to `CryptoPublicKey`, so we can pass them to a _Supreme_ verifier:

```kotlin
--8<-- "indispensable-josef/src/jvmTest/kotlin/at/asitplus/signum/examples/JoseExamples.kt:jose-jwk"
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
