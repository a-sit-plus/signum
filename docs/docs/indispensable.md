![Indispensable](assets/core-dark-large.png#only-light)
![Indispensable](assets/core-light-large.png#only-dark)

[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus.signum/indispensable?label=maven-central)](https://mvnrepository.com/artifact/at.asitplus.signum.indispensable/)

# Indispensable Core Data Structures and Functions for Cryptographic Material

This [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library provides platform-independent data
types and functionality related to crypto and PKI applications:

* EC Math
  * EC Point Class
    * EC Curve Class
    * Mathematical operations
    * Bit Length
    * Point Compression
* Public Keys (RSA and EC)
* Algorithm Identifiers (Signatures, Hashing)
* X509 Certificate Class (create, encode, decode)
  * Extensions
    * Alternative Names
    * Distinguished Names
* Certification Request (CSR)
    * CSR Attributes
* Exposes Multibase Encoder/Decoder as an API dependency
  including [Matthew Nelson's smashing Base16, Base32, and Base64 encoders](https://github.com/05nelsonm/encoding)


In effect, you can work with X509 Certificates, public keys, CSRs and arbitrary ASN.1 structures on the JVM, Android, and iOS.

!!! tip
    **Do check out the full API docs [here](dokka/indispensable/index.html)**!

## Using it in your Projects

This library was built for [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html). Currently, it targets
the JVM, Android and iOS.

Simply declare the desired dependency to get going:

```kotlin 
implementation("at.asitplus.signum:indispensable:$version")
```

## Structure and Class Overview
As the name _Indispensable_ implies, this is the base module for all KMP crypto operations.
It includes types, abstractions, and functionality considered absolutely essential to even entertain the thought
of working with and on cryptographic data.

### Package Organisation

#### Fundamental Cryptographic Data Structures
The main package housing all data classes is `at.asitplus.signum.indispensable`.
It contains essentials such as:

* `CryptoPublicKey` representing a public key. Currently, we support RSA and EC public keys on NIST curves.
* `Digest` containing an enumeration of supported
* `ECCurve` representing an EC Curve
* `ECPoint` representing a point on an elliptic curve
* `CryptoSignatre` representing a cryptographic signature including descriptive information regarding the algorithms and signature data
* `SignatureAlgorithm` containing an enumeration of supported signature algorithms
    * `X509SignatureAlgorithm` enumeration of supported X.509 signature algorithms (maps to and from `SignatureAlgorithm`)
* `Attestation` representing a container to convey attestation statements 
    * `AndroidKeystoreAttestation` contains the certificate chain from Google's root certificate down to the attested key
    * `IosHomebrewAttestation` contains the new iOS attestation format introduces in Supreme 0.2.0 (see the [Attestation](supreme.md#attestation) section of the _Supreme_ manual for details).
    * `SelfAttestation` is used on the JVM. It has no specific semantics, but could be used, if an attestation-supporting HSM is used on the JVM. WIP!

#### PKI-Related data Structures
The `pki` package contains data classes relevant in the PKI context:

* `X509Certificate` does what you think it does
    * `X509CertificateExtension` contains a convenience abstraction of X.509 certificate extensions 
    * `AlternativeNames` contains definitions of subject/issuer alternative names
    * `RelativeDistinguishedName` contains definitions of RDNs (Common Name, City, …)
* `Pkcs10CertificateRequest` contains a CSR abstraction
    * `Pcs10CertificateRequestAttributes` contains a CSR attribute extension

##  Conversion from/to platform types

Obviously, a world outside this library's data structures exists.
The following functions provide interop functionality with platform types.

### JVM/Android

* `SignatureAlgorithm.getJCASignatureInstance()` gets a pre-configured JCA instance for this algorithm
* `SpecializedSignatureAlgorithm.getJCASignatureInstance()` gets a pre-configured JCA instance for this algorithm
* `SignatureAlgorithm.getJCASignatureInstancePreHashed()` gets  a pre-configured JCA instance for pre-hashed data for this algorithm
* `SpecializedSignatureAlgorithm.getJCASignatureInstancePreHashed()` gets  a pre-configured JCA instance for pre-hashed data for this algorithm

* `Digest.jcaPSSParams` returns a sane default `PSSParameterSpec` for computing PSS signatures
* `Digest.jcaName` returns the JCA name of the digest
* `Digest?.jcaAlgorithmComponent` digest part of the digest part of the <Digest>with<Algorithm> JCA algorithm identifier (which differs fom the above)

* `ECCurve.jcaName` returns the curve's name used by JCA
* `ECCurve.byJcaName()` returns the curve matching the provided JCA curve name

* `CryptoPublicKey.getJcaPublicKey()` returns the JCA-representation of the public key
* `CryptoPublicKey.EC.getJcaPublicKey()` returns the JCA-representation of the public key (convenience helper)
* `CryptoPublicKey.RSA.getJcaPublicKey()` returns the JCA-representation of the public key (convenience helper)
* `CryptoPublicKey.fromJcaPublicKey` creates a `CryptoPublicKey` from a JCA Public Key
* `CryptoPublicKey.EC.fromJcaPublicKey` creates a `CryptoPublicKey.EC` from a JCA EC Public Key
* `CryptoPublicKey.RSA.fromJcaPublicKey` creates a `CryptoPublicKey.RSA` from a JCA RSA Public Key

* `CryptoSignature.jcaSignatureBytes` returns the JCA-native encoded representation of a signature
* `CryptoSignature.parseFromJca()` returns a signature object form a JCA-native encoded representation of a signature
* `CryptoSignature.EC.parseFromJca()` returns an EC signature object form a JCA-native encoded representation of a signature
* `CryptoSignature.RSAorHMAC.parseFromJca()` returns an RSA signature object form a JCA-native encoded representation of a signature
* `CryptoSignature.EC.parseFromJcaP1363` parses a signature produced by the JCA digestWithECDSAinP1363Format algorithm.
* `X509Certificate.toJcaCertificate()` converts the certificate to a JCA-native `X509Certificate`
* `java.security.cert.X509Certificate.toKmpCertificate()` converts a JCA-native certificate to a Signum `X509Certificate`

### iOS

* `CryptoPublicKey.iosEncoded` encodes a public key as iOS does
* `CryptoPublicKey.fromiosEncoded()` decodes a public key that was encoded in iOS

* `SignatureAlgorithm.secKeyAlgorithm` returns an algorithm identifier constant usable with CommonCrypto
* `SpecializedSignatureAlgorithm.secKeyAlgorithm` returns an algorithm identifier constant usable with CommonCrypto
* `SpecializedSignatureAlgorithm.secKeyAlgorithm` returns an algorithm identifier constant usable with CommonCrypto
* `SignatureAlgorithm.secKeyAlgorithmPreHashed` returns an algorithm identifier constant usable with CommonCrypto (for pre-hashed data)
* `SpecializedSignatureAlgorithm.secKeyAlgorithmPreHashed` returns an algorithm identifier constant usable with CommonCrypto (for pre-hashed data)

* `CryptoSignature.iosEncoded` encodes a signature object as iOS would natively do


## ASN.1 Engine Addons

Relevant classes like `CryptoPublicKey`, `X509Certificate`, `Pkcs10CertificationRequest`, etc. all
implement `Asn1Encodable` and their respective companions implement `Asn1Decodable`.
This is an essential pattern, making the ASN.1 engine work the way it does.
We have opted against using kotlinx.serialization for maximum flexibility and more convenient debugging.  
The following section provides more details on the various patterns used for ASN.1 encoding and decoding.

### Generic Patterns

As mentioned before, classes like `CryptoPublicKey`, `X509Certificate`, and `ObjectIdentifier` all implement `Asn1Encodable`
while their companions implement `Asn1Decodable`.
These interfaces essentially provide a mapping between custom types and low-level TLV structures that can directly be encoded, conforming to DER.
This also means, a direct serialization of such custom types is valuable for debugging, but not for encoding.
**Hence, decoding a kotlinx.serialization output of those classes is unsupported.**

#### Low-Level Addons

This module provides the following low-level addons:

* `Asn1Primitive.decodeToBigInteger()` throws on error
* `Asn1Primitive.decodeToBigIntegerOrNull()` returns `null` on error
* `BigInteger.decodeFromAsn1ContentBytes()`
* `encodeToAsn1Primitive()` produces an ASN.1 primitive  `BigInteger`
* `encodeToAsn1ContentBytes()` producing the content bytes of an `Asn1Primitive` for `BigInteger`
