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
* Private Keys (RSA and EC)
* KDF definitions for HKDF, PBKDF2, and scrypt
* Algorithm Identifiers (Signatures, Hashing)
* X509 Certificate Class (create, encode, decode)
  * Extensions
    * Alternative Names
    * Distinguished Names
* Certification Request (CSR)
    * CSR Attributes
* Exposes Multibase Encoder/Decoder as an API dependency
  including [Matthew Nelson's smashing Base16, Base32, and Base64 encoders](https://github.com/05nelsonm/encoding)

In effect, you can work with X509 Certificates, public keys, CSRs and Signum-specific cryptographic structures on all KMP targets except `watchosDeviceArm64`!

!!! tip
    **Do check out the full API docs [here](dokka/indispensable/index.html)**!

## Using it in your Projects

This library was built for [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html). Currently, it targets
the JVM, Android and iOS.

Simply declare the desired dependency to get going:

Use `at.asitplus.signum:indispensable:4.0.0`.

## Structure and Class Overview
As the name _Indispensable_ implies, this is the base module for all KMP crypto operations.
It includes types, abstractions, and functionality considered absolutely essential to even entertain the thought
of working with and on cryptographic data.

### Package Organisation

#### Fundamental Cryptographic Data Structures
The base package is `at.asitplus.signum.indispensable`; concrete operations and algorithm definitions live in its subpackages.
It contains essentials such as:

* `CryptoPublicKey` representing a public key. Currently, we support RSA and EC public keys on NIST curves.
* `CryptoPrivateKey` representing a private key. Currently, we support RSA (`RsaPrivateKey`) and EC (`EcdsaPrivateKey`) private keys on NIST curves. RSA keys always include the public key, EC keys may or may not contain a public key and/or curve.
    * Has an additional specialization `CryptoPrivateKey.WithPublicKey` that always includes a public key
    * Encodes to PKCS#8 by default
    * RSA keys also support PKCS#1 encoding (`.asPKCS1`)
    * EC keys also support SEC1 encoding (`.asSEC1`)
* `Digest` defines an open digest interface; built-in SHA definitions live in `indispensable.digest`
* `ECCurve` representing an EC Curve
* `ECPoint` representing a point on an elliptic curve
* `CryptoSignature` representing a cryptographic signature holding parsed signature data; `SignatureValue` holds an uninterpreted X.509 signature value
* `SignatureAlgorithm` is an open signature algorithm interface; EC and RSA definitions live in `indispensable.sign`
* `Attestation` representing a container to convey attestation statements 
    * `AndroidKeystoreAttestation` contains the Android key-attestation certificate chain
    * `IosHomebrewAttestation` contains the iOS App Attest format used by Supreme (see the [Attestation](supreme.md#attestation) section of the _Supreme_ manual for details).
    * `SelfAttestation` is used on the JVM. It carries a self-signed certificate and does not establish hardware trust.
* `KeyAgreementPrivateValue` denotes what the name implies. Currently, only ECDH is implemented, hence, there is a single subinterface `KeyAgreementPrivateValue.ECDH`,
which is implemented by `EcdsaPrivateKey`
* `KeyAgreementPublicValue` denotes what the name implies. Currently, only ECDH is implemented, hence, there is a single subinterface `KeyAgreementPublicValue.ECDH`,
which is implemented by `EcdsaPublicKey`
* `MessageAuthenticationCode` defines the interface for message authentication codes
    * `HMAC` defines HMAC for all supported `Digest` algorithms. The [Supreme](supreme.md) KMP crypto provider implements the actual HMAC functionality.
* `KDF` defines the interface for key derivation functions
    * `HKDF` defines the configuration of an HKDF key derivation function. The [Supreme](supreme.md) KMP crypto provider implements the actual derivation functionality.
    * `PBKDF2` defines the configuration of an PBKDF2 key derivation function. The [Supreme](supreme.md) KMP crypto provider implements the actual derivation functionality.
    * `SCrypt` defines the configuration of an scrypt key derivation function. The [Supreme](supreme.md) KMP crypto provider implements the actual derivation functionality.
* `SymmetricEncryptionAlgorithm` represents symmetric encryption algorithms. Built-in definitions include AES-GCM, AES-CBC, AES-CBC-HMAC, AES-ECB and AES key wrap. [Supreme](supreme.md) supplies the actual operations.
    * `AuthCapability` tracks whether authentication is integrated, absent, or uses a dedicated MAC key.
    * `NonceTrait` tracks whether an algorithm requires a nonce/IV.
    * `KeyType` describes the key material required by the algorithm.
* `Ciphertext` and `SealedBox` store encrypted data and algorithm-appropriate nonce, authentication tag and AAD information in the `symmetric` package.

#### PKI-Related Data Structures
The `pki` package contains data classes relevant in the PKI context:

* `Certificate` and `TbsCertificate` represent an X.509 certificate and its signed contents.
* `CertificateExtension` holds an extension; typed extensions live in [Indispensable PKIX](indispensable-pkix.md).
* `X500Name`, `RelativeDistinguishedName`, and `AttributeTypeAndValue` represent distinguished names.
* `CertificationRequest`, `TbsCertificationRequest`, and `CsrAttribute` represent PKCS#10 requests and attributes.

Issuer and subject names use `Name`; construct an X.509 name with `X500Name(rdns)` and access its
RDNs through `relativeDistinguishedNames`. Certificate validity uses `kotlin.time.Instant` and serial
numbers use `Asn1Integer.Positive`. CSR constructors omit the version, which is always 0.
Raw attribute values are available through the `pki.value` extension; `pki.asn1Representation`
provides the corresponding awesn1 model.

Concrete EC/RSA keys and signatures live in `indispensable.sign`. Digest, MAC, KDF, agreement,
and encryption definitions have their own packages. These are data and configuration APIs;
[Supreme](supreme.md) supplies cryptographic implementations.

## Core Provider Initialization

For applications using only Indispensable, import `at.asitplus.signum.indispensable.installIndispensable`
and call `Signum.installIndispensable()` during startup before using provider-based platform conversions.
Several semantic companion objects install core providers lazily, but decoding a certificate alone does not
ensure that the JCA key-mapping providers have been installed. Applications using Supreme can instead
call `Signum.installSupreme()`, which installs the core providers too.

##  Conversion from/to Platform Types

Obviously, a world outside this library's data structures exists.
The following functions provide interop functionality with platform types.

### JVM/Android

* `CryptoPublicKey.toJcaPublicKey()` and `PublicKey.toCryptoPublicKey()` convert public keys.
* `CryptoPrivateKey.toJcaPrivateKey()` and `PrivateKey.toCryptoPrivateKey()` convert private keys.
* `Certificate.toJcaCertificate()` is suspending; `toJcaCertificateBlocking()` is available when a blocking API is required.
* `java.security.cert.X509Certificate.toKmpCertificate()` converts back to Signum.
* `ECCurve.jcaName`, `ECCurve.byJcaName()`, and the platform algorithm helpers connect built-in definitions with JCA.

Key conversions and `toJcaCertificateBlocking()` return values directly.
`X509Certificate.toKmpCertificate()` still returns `KmmResult`.


```kotlin
--8<-- "indispensable/src/jvmTest/kotlin/at/asitplus/signum/examples/CoreExamples.kt:core-key-roundtrip"
```

1. Decoding gives a semantic Signum key. The original format representation is retained when available.

### iOS

* `CryptoPublicKey.iosEncoded` exports the platform representation; `CryptoPublicKey.fromIosEncoded()` parses it.
* `CryptoPrivateKey.toSecKey()` produces a `SecKey`; `SecKeyRef.toCryptoPrivateKey()` imports a native key.
* `SignatureAlgorithm.secKeyAlgorithm` and `secKeyAlgorithmPreHashed` obtain native algorithm identifiers through the platform extension providers.
* `CryptoSignature.iosEncoded` exposes the native signature representation.

Native key encodings do not always contain every piece of algorithm metadata. In particular,
Apple EC exports omit the curve identifier, so retain the algorithm/curve context or use the
provided curve-length helpers for supported built-in curves.

## Encoding and Format Representations

Relevant classes like `CryptoPublicKey`, `CryptoPrivateKey`, `Certificate`, and `CertificationRequest`
implement `Encodable`; their companions implement `Decodable`. Encoding goes through the contextual
`Signum.Der` serializer. `Signum.Der.encodeToPem(value)` and `Signum.Der.decodeFromPem<T>(pem)` provide PEM transport for
supported types, with helpers imported from `at.asitplus.signum.indispensable`. For byte arrays, import
`kotlinx.serialization.encodeToByteArray` and `kotlinx.serialization.decodeFromByteArray`. For ASN.1
elements, import `at.asitplus.awesn1.serialization.encodeToTlv` and `decodeFromTlv`.

`Encodable` and `Decodable` do not supply encoding methods. Custom ASN.1 structures can keep awesn1's
`Asn1Encodable`/`Asn1Decodable` contracts and use its low-level codecs. When embedding a semantic
Signum value into an awesn1 builder, add `Signum.Der.encodeToTlv(value)` instead of the value itself.

`asn1Representation` exposes the awesn1 wire model, while `sourceRepresentation` records a decoded
representation. Semantic equality does not require byte-identical encodings. Constructing a new value
(or copying changed semantics) does not mean it inherits the original signed bytes. Verify signatures
against the actual input representation and use the supplied signing/verification helpers.

ECDSA uses DER for its X.509 signature value and fixed-width P1363 bytes for JOSE and COSE:

```kotlin
--8<-- "indispensable/src/jvmTest/kotlin/at/asitplus/signum/examples/CoreExamples.kt:core-signature-formats"
```

The ASN.1 parser, DER codec, low-level types, builder DSL and OID catalogue belong to
[awesn1](https://github.com/a-sit-plus/awesn1). Signum adds cryptographic semantics, contextual
serialization and [extensibility](extensibility.md) integration on top of those models.
