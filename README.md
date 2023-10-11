# 🔥🔥🔥KMP Crypto🔥🔥🔥

[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-brightgreen.svg?style=flat)](http://www.apache.org/licenses/LICENSE-2.0)
[![Kotlin](https://img.shields.io/badge/kotlin-multiplatform-orange.svg?logo=kotlin)](http://kotlinlang.org)
[![Kotlin](https://img.shields.io/badge/kotlin-1.9.10-blue.svg?logo=kotlin)](http://kotlinlang.org)
[![Java](https://img.shields.io/badge/java-11+-blue.svg?logo=OPENJDK)](https://www.oracle.com/java/technologies/downloads/#java11)
[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus/kmp-crypto)](https://mvnrepository.com/artifact/at.asitplus.kmp-crypto/)

## Kotlin Multiplatform Crypto/PKI library with ASN1 Parser and Encoder

_(We are not doing the Prince thing; the emojis are not part of the project name)_

This [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library provides platform-independent data
types and functionality related to crypto and PKI applications:

* Public Keys (RSA and EC)
* Algorithm Identifiers (Signatures, Hashing)
* X509 Certificate Class (create, encode, decode)
* Certification Request (CSR)
* ObjectIdentifier Class with human-readable notation (e.g. 1.2.9.6245.3.72.13.4.7.6)
* Generic ASN.1 abstractions to operate on and create arbitrary ASN.1 Data
* JWS-related data structures (Json Web Keys, JWT, etc…)
* COSE-related data structures (Cose Keys, CWT, et…)
* Serializability of all data classes for debugging
* **ASN.1 Parser and Encoder including a DSL to generate ASN.1 structures**

This last bit means that
**you can work with X509 Certificates, Public Keys, CSRs and arbitrary ASN.1 structures on iOS.**

## Architecture

This library was built for [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html). Its primary targets
are JVM, Android and iOS.

See also [DEVELOPMENT.md](DEVELOPMENT.md)

## Limitations

As this library provides multiplatform data types to help interop with platform-specific crypto functionality, it does
not provide any functionality to carry out the actual cryptographic operations.
Also, it provides no abstractions for private keys, because those should never leave a system in the first place.

While a multiplatform crypto provider would be awesome, this sort fo things also needs a careful design phase before
even entertaining the thought of implementing such functionality. It therefore not planned at the time of this writing (
2023-10)

While the ASN.1 perser will happily parse any valid ASN.1 structure you throw at it and write it back correctly too, 
higher-level abstractions (such as X509Certificate) are too lenient in some aspectes and too strict in others.
For example: DSA-signed certificates will not parse to an instance of `X509Certificate`.
At the same time, the certificates containing the same extension multiple times will work file too
 