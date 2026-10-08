<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/docs/assets/signum-light-large.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/docs/assets/signum-dark-large.png">
  <img alt="Signum – Kotlin Multiplatform Crypto/PKI Library" src="docs/docs/assets/signum-dark-large.png">
</picture>


# Signum – Kotlin Multiplatform Crypto/PKI Library

[![A-SIT Plus Official](https://raw.githubusercontent.com/a-sit-plus/a-sit-plus.github.io/709e802b3e00cb57916cbb254ca5e1a5756ad2a8/A-SIT%20Plus_%20official_opt.svg)](https://plus.a-sit.at/open-source.html)
[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-brightgreen.svg?style=flat)](http://www.apache.org/licenses/LICENSE-2.0)
[![Kotlin](https://img.shields.io/badge/kotlin-multiplatform-orange.svg?logo=kotlin)](http://kotlinlang.org)
[![Kotlin](https://img.shields.io/badge/kotlin-2.4.0-blue.svg?logo=kotlin)](http://kotlinlang.org)
[![Java](https://img.shields.io/badge/java-17+-blue.svg?logo=OPENJDK)](https://www.oracle.com/java/technologies/downloads/#java17)
[![iOS](https://img.shields.io/badge/iOS-15-white?logo=apple)](https://support.apple.com/en-gb/108051)

| [![Android](https://img.shields.io/badge/Android_(indispensable)-SDK--26-37AA55?logo=android)](https://developer.android.com/tools/releases/platforms#8.0) |  [![Maven Central (indispensable)](https://img.shields.io/maven-central/v/at.asitplus.signum/indispensable?label=maven-central%20%28indispensable%29)](https://mvnrepository.com/artifact/at.asitplus.signum/)  |  [![Maven SNAPSHOT (indispensable)](https://img.shields.io/nexus/snapshots/https/s01.oss.sonatype.org/at.asitplus.signum/indispensable?label=SNAPSHOT%20%28indispensable%29)](https://s01.oss.sonatype.org/content/repositories/snapshots/at/asitplus/signum/indispensable/)  |
|:----------------------------------------------------------------------------------------------------------------------------------------------------------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
|    [![Android](https://img.shields.io/badge/Android_(Supreme)-SDK--30-37AA55?logo=android)](https://developer.android.com/tools/releases/platforms#11)     |       [![Maven Central (Supreme)](https://img.shields.io/maven-central/v/at.asitplus.signum/supreme?label=maven-central%20%28Supreme%29)](https://mvnrepository.com/artifact/at.asitplus.signum/supreme)        |              [![Maven SNAPSHOT (Supreme)](https://img.shields.io/nexus/snapshots/https/s01.oss.sonatype.org/at.asitplus.signum/supreme?label=SNAPSHOT%20%28Supreme%29)](https://s01.oss.sonatype.org/content/repositories/snapshots/at/asitplus/signum/supreme/)              |


</div>

## Kotlin Multiplatform Crypto/PKI Library

This [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library provides platform-independent data
types and platform-native functionality related to crypto and PKI applications:

* **Multiplatform, platform-native crypto** &rarr; Check out the included [CMP demo App](https://a-sit-plus.github.io/signum/app/) to see it in action!
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
* **[Hybrid Public Key Encryption (HPKE)](https://a-sit-plus.github.io/signum/supreme/#hybrid-public-key-encryption)**
* JOSE-related data structures (JSON Web Keys, JWT, etc…)
* COSE-related data structures (COSE Keys, CWT, etc…)
* Exposes Multibase Encoder/Decoder as an API dependency
  including [Matthew Nelson's smashing Base16, Base32, and Base64 encoders](https://github.com/05nelsonm/encoding)

The ASN.1 engine has become its own library, [awesn1](https://a-sit-plus.github.io/awesn1/).
Signum builds its key, certificate, and CSR serialization on top of it; arbitrary ASN.1 structures and the builder DSL
are documented over there. Which means that you can still share your cryptographic data structures across platforms,
while using the engine independently of Signum.

**We also provide comprehensive API docs [here](https://a-sit-plus.github.io/signum/dokka/)**!

## Using it in your Projects

The data modules support a broad range of KMP targets. The _Supreme_ crypto provider targets the JVM, Android, and iOS.
The [feature matrix](https://a-sit-plus.github.io/signum/features/) describes operations and platform restrictions.

This library consists of six public modules:

| Name | Info |
|:-----|:-----|
| **[Indispensable](https://a-sit-plus.github.io/signum/indispensable/)** | Base module containing cryptographic data structures, open algorithm interfaces, keys, certificates and CSRs. Uses awesn1 for serialization. |
| **[Indispensable Josef](https://a-sit-plus.github.io/signum/indispensable-josef/)** | JOSE add-on module containing JWS/E/T-specific data structures and extensions to convert from/to core types. Includes the required kotlinx.serialization magic. |
| **[Indispensable Cosef](https://a-sit-plus.github.io/signum/indispensable-cosef/)** | COSE add-on module containing COSE/CWT-specific data structures and extensions to convert from/to core types. Includes the required kotlinx.serialization magic. |
| **[Indispensable PKIX](https://a-sit-plus.github.io/signum/indispensable-pkix/)** | Typed certificate extensions, X.500 and general names, trust-anchor data and a bundled trust store. |
| **[Supreme](https://a-sit-plus.github.io/signum/supreme/)** | KMP crypto provider implementing platform-native operations and hardware-backed signing on mobile platforms. |
| **[PKIX Supreme](https://a-sit-plus.github.io/signum/pkix-supreme/)** | Certificate path construction and validation, with access to platform trust stores. |

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

Already using Signum 3.x? Start with the [migration guide](https://a-sit-plus.github.io/signum/migration/).
This is a major refactor, including the awesn1 extraction and extensibility throughout the library.

Signum uses the [Modulator Gradle plugin](https://github.com/a-sit-plus/modulator) for optional integration modules.
See the [manual](https://a-sit-plus.github.io/signum/#modulator) for automatic bridge selection and explicit dependencies.

## Rationale

Looking for a KMP cryptography framework, you have undoubtedly come across
[cryptography-kotlin](https://github.com/whyoleg/cryptography-kotlin). So have we and it is a powerful library.
This begs the question: Why implement another, incompatible cryptography framework from scratch?
The short answer is: Signum and cryptography-kotlin pursue different goals and priorities.
Signum focuses on tight platform integration (**including hardware-backed crypto and attestation!**),
and comprehensive PKI, JOSE, and COSE support.

<details>
<summary>More…</summary>
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
Refer to [Extensibility](https://a-sit-plus.github.io/signum/extensibility/) for the process; the built-in algorithms remain available with sensible defaults.

</details>

## Examples and API Documentation

Do check out the [full manual](https://a-sit-plus.github.io/signum/)!
It has separate sections for each module, provides examples, and a full API documentation.
The examples live in the modules' test sources and are embedded into the manual, so the displayed code is the code we test.
For local documentation builds, see [docs/README.md](docs/README.md).

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
