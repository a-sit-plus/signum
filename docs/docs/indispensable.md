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

In effect, you can work with X509 Certificates, public keys, CSRs and arbitrary ASN.1 structures on all KMP targets except `watchosDeviceArm64`!

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
* `CryptoPrivateKey` representing a private key. Currently, we support RSA (`CryptoPrivateKey.RSA`) and EC (`CryptoPrivateKey.EC`) private keys on NIST curves. RSA keys always include the public key, EC keys may or may not contain a public key and/or curve.
    * Has an additional specialization `CryptoPrivateKey.WithPublicKey` that always includes a public key
    * Encodes to PKCS#8 by default
    * RSA keys also support PKCS#1 encoding (`.asPKCS1`)
    * EC keys also support SEC1 encoding (`.asSEC1`)
* `Digest` containing an enumeration of supported digests
* `ECCurve` representing an EC Curve
* `ECPoint` representing a point on an elliptic curve
* `CryptoSignatre` representing a cryptographic signature including descriptive information regarding the algorithms and signature data
* `SignatureAlgorithm` containing an enumeration of supported signature algorithms
    * `X509SignatureAlgorithm` enumeration of supported X.509 signature algorithms (maps to and from `SignatureAlgorithm`)
* `Attestation` representing a container to convey attestation statements 
    * `AndroidKeystoreAttestation` contains the certificate chain from Google's root certificate down to the attested key
    * `IosHomebrewAttestation` contains the new iOS attestation format introduces in Supreme 0.2.0 (see the [Attestation](supreme.md#attestation) section of the _Supreme_ manual for details).
    * `SelfAttestation` is used on the JVM. It has no specific semantics, but could be used, if an attestation-supporting HSM is used on the JVM. WIP!
* `KeyAgreementPrivateValue` denotes what the name implies. Currently, only ECDH is implemented, hence, there is a single subinterface `KeyAgreementPrivateValue.ECDH`,
which is implemented by `CryptoPrivateKey.EC`
* `KeyAgreementPublicValue` denotes what the name implies. Currently, only ECDH is implemented, hence, there is a single subinterface `KeyAgreementPublicValue.ECDH`,
which is implemented by `CryptoPublicKey.EC`
* `MAC` defines the interface for message authentication codes
    * `HMAC` defines HMAC for all supported `Digest` algorithms. The [Supreme](supreme.md) KMP crypto provider implements the actual HMAC functionality.
* `KDF` defines the interface for key derivation functions
    * `HKDF` defines the configuration of an HKDF key derivation function. The [Supreme](supreme.md) KMP crypto provider implements the actual derivation functionality.
    * `PBKDF2` defines the configuration of an PBKDF2 key derivation function. The [Supreme](supreme.md) KMP crypto provider implements the actual derivation functionality.
    * `SCrypt` defines the configuration of an scrypt key derivation function. The [Supreme](supreme.md) KMP crypto provider implements the actual derivation functionality.
* `SymmetricEncryptionAlgorithm` represents symmetric encryption algorithms. _Indispensable_ currently ships with definitions for AES-CBC, a flexible AES-CBC-HMAC, and AES-GCM, while the [Supreme](supreme.md) KMP crypto provider implements the actual AES functionality. 
    * `BlockCipher` denotes a BlockCipher 
    * `WithIV` denotes a Cipher requiring an initialization vector
    * `Unauthenticated` denotes a non-authenticated encryption algorithm
    * `Authenticated` denotes an authenticated encryption algorithm
    * `Authenticated.WithDedicatedMac` describes an encryption authenticated encryption algorithm based on a non-authenticated one and a dedicated `MAC`, to achieve authenticated encryption
* `Ciphertext` stores ciphertext produced by a symmetric cipher. It has dedicated accessors for every component of the ciphertext, such as `iv` and `encryptedData`
    * `Unauthenticated` denotes a ciphertext produced by a `SymmetricEncryptionAlgorithm.Unauthenticated`
    * `Authenticated` denotes a ciphertext produced by a `SymmetricEncryptionAlgorithm.Authenticated`, it also contains an `authTag` and, `aad`
    * `Authenticated.WithDedicatedMac` restricts `Ciphertext.Authenticated` to ciphertexts produced by a `SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac`

#### PKI-Related Data Structures
The `pki` package contains data classes relevant in the PKI context:

* `X509Certificate` does what you think it does
    * `X509CertificateExtension` contains a convenience abstraction of X.509 certificate extensions 
    * `AlternativeNames` contains definitions of subject/issuer alternative names
    * `RelativeDistinguishedName` contains definitions of RDNs (Common Name, City, …)
* `Pkcs10CertificateRequest` contains a CSR abstraction
    * `Pcs10CertificateRequestAttributes` contains a CSR attribute extension

#### Notes on Object Identifiers
In addition to PKI-related data structures, a (rather bloated) `KnownOIDs` object is available.
It contains all ASN.1 object identifiers from Peter Guttmann's
[dumpasn1.cfg](https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg).
Hence, handy constants such as `KnwonOIDs.ecdsaWithSHA256` are available, but also rather obscure ones such as
`KnownOIDs.asAdjacencyAttest`.

`KnownOIDs` also contains human-readable descriptions of all `KnownOIDs` constants, which tie into exposed through the `ObjectIdentifier.describe()` mechanism:
One call to `ObjectIdentifer.Companion.describeKnownOIDs()` attaches descrptions to all OIDs contained in `KnwonOIDs` (subsequent calls are a NOOP).
This is useful for debugging, but never called by default.

On the one hand, it is convenient to have virtually the whole world's OIDs available as constants including descriptions.
On the other hand, this will add a couple of megabytes to klibs and any XCode frameworks. Hence, the OID constants and descriptions live in
a discrete module `indispensable-oids`. If desired, custom XC frameworks can be exported that don't include this module to save a few megabytes.

##  Conversion from/to Platform Types

Obviously, a world outside this library's data structures exists.
The following functions provide interop functionality with platform types.

### JVM/Android

* `SignatureAlgorithm.getJCASignatureInstance()` gets a pre-configured JCA instance for this algorithm
* `SpecializedSignatureAlgorithm.getJCASignatureInstance()` gets a pre-configured JCA instance for this algorithm
* `SignatureAlgorithm.getJCASignatureInstancePreHashed()` gets  a pre-configured JCA instance for pre-hashed data for this algorithm
* `SpecializedSignatureAlgorithm.getJCASignatureInstancePreHashed()` gets  a pre-configured JCA instance for pre-hashed data for this algorithm

<br>

* `Digest.jcaPSSParams` returns a sane default `PSSParameterSpec` for computing PSS signatures
* `Digest.jcaName` returns the JCA name of the digest
* `Digest?.jcaAlgorithmComponent` digest part of the digest part of the <Digest>with<Algorithm> JCA algorithm identifier (which differs fom the above)

<br>

* `ECCurve.jcaName` returns the curve's name used by JCA
* `ECCurve.byJcaName()` returns the curve matching the provided JCA curve name
* `ECCurve.iosEncodedPublicKeyLength` returns the number of bytes of a public key matching this curve, when exporting such a key from iOS.
* `ECCurve.iosEncodedPrivateKeyLength` returns the number of bytes of a private key matching this curve, when exporting such a key from iOS.
* `ECCurve.fromIosEncodedPublicKeyLength`returns the curve matching the length of an encoded public key, when exported from iOS.
(Apple does not encode curve identifiers, when exporting keys.)
* `ECCurve.fromIosEncodedPrivateKeyLength` returns the curve matching the length of an encoded private key, when exported from iOS.
(Apple does not encode curve identifiers, when exporting keys.)

<br>

* `CryptoPublicKey.toJcaPublicKey()` returns the JCA-representation of the public key
* `CryptoPublicKey.EC.toJcaPublicKey()` returns the JCA-representation of the public key (convenience helper)
* `CryptoPublicKey.RSA.toJcaPublicKey()` returns the JCA-representation of the public key (convenience helper)
* `PublicKey.toCryptoPublicKey()` creates a `CryptoPublicKey` from a JCA Public Key
* `ECPublicKey.toCryptoPublicKey()` creates a `CryptoPublicKey.EC` from a JCA EC Public Key
* `RSAPublicKey.toCryptoPublicKey()` creates a `CryptoPublicKey.RSA` from a JCA RSA Public Key

<br>

* `CryptoPrivateKey.WihtPublicKey<*>.toJcaPublicKey()` returns the JCA-representation of the private key
* `CryptoPrivateKey.EC.WithPublicKey.toJcaPublicKey()` returns the JCA-representation of the private key (convenience helper)
* `CryptoPrivateKey.RSA.toJcaPublicKey()` returns the JCA-representation of the private key (convenience helper)
* `PrivateKey.toCryptoPrivateKey()` creates a `CryptoPrivateKey.WithPublicKey<*>` from a JCA Public Key
* `ECPrivateKey.toCryptoPrivateKey()` creates a `CryptoPrivateKey.EC.WithPublicKey` from a JCA EC Public Key
* `RSAPrivateKey.toCryptoPrivateKey()` creates a `CryptoPrivateKey.RSA` from a JCA RSA Public Key

<br>

* `CryptoSignature.jcaSignatureBytes` returns the JCA-native encoded representation of a signature
* `CryptoSignature.parseFromJca()` returns a signature object form a JCA-native encoded representation of a signature
* `CryptoSignature.EC.parseFromJca()` returns an EC signature object form a JCA-native encoded representation of a signature
* `CryptoSignature.RSA.parseFromJca()` returns an RSA signature object form a JCA-native encoded representation of a signature
* `CryptoSignature.EC.parseFromJcaP1363` parses a signature produced by the JCA digestWithECDSAinP1363Format algorithm.
* `X509Certificate.toJcaCertificate()` converts the certificate to a JCA-native `X509Certificate`
* `java.security.cert.X509Certificate.toKmpCertificate()` converts a JCA-native certificate to a Signum `X509Certificate`

### iOS

* `CryptoPublicKey.iosEncoded` encodes a public key as iOS does
* `CryptoPublicKey.fromIosEncoded()` decodes a public key that was encoded in iOS

<br>

* `CryptoPrivateKey.toSecKey()` produces a `SecKey` usable on iOS
* `CryptoPrivateKey.fromIosEncoded()` decodes a private key as it is exported from iOS

<br>

* `SignatureAlgorithm.secKeyAlgorithm` returns an algorithm identifier constant usable with CommonCrypto
* `SpecializedSignatureAlgorithm.secKeyAlgorithm` returns an algorithm identifier constant usable with CommonCrypto
* `SpecializedSignatureAlgorithm.secKeyAlgorithm` returns an algorithm identifier constant usable with CommonCrypto
* `SignatureAlgorithm.secKeyAlgorithmPreHashed` returns an algorithm identifier constant usable with CommonCrypto (for pre-hashed data)
* `SpecializedSignatureAlgorithm.secKeyAlgorithmPreHashed` returns an algorithm identifier constant usable with CommonCrypto (for pre-hashed data)

* `CryptoSignature.iosEncoded` encodes a signature object as iOS would natively do


## ASN.1 Engine Addons

Relevant classes like `CryptoPublicKey`, `CryptoPrivateKey`, `X509Certificate`, `Pkcs10CertificationRequest`, etc. all
implement `Asn1Encodable` and their respective companions implement `Asn1Decodable`.
This is an essential pattern, making the ASN.1 engine work the way it does.
We have opted against using kotlinx.serialization for maximum flexibility and more convenient debugging.  
The following section provides more details on the various patterns used for ASN.1 encoding and decoding.

### Generic Patterns

As mentioned before, classes like `CryptoPublicKey`, `X509Certificate`, and `ObjectIdentifier` all implement `Asn1Encodable`
while their companions implement `Asn1Decodable`.
These interfaces essentially provide a mapping between custom types and low-level TLV structures that can directly be encoded, conforming to DER.

In addition, `CryptoPublicKey`, `CryptoPrivateKey`, `X509Certificate`, `Pkcs10CertificationRequest` also implement `PemEncodable`,
while their respective companions implement `PemDecodable`.
This brings about the `encodeToPem` and `decodeFromPem` functions doing what their names imply:
Encode/decode to/from PEM strings.

#### Low-Level Addons

This module provides the following low-level addons for [Kotlin MP BigNum](https://github.com/ionspin/kotlin-multiplatform-bignum):

* `Asn1Primitive.decodeToBigInteger()` throws on error
* `Asn1Primitive.decodeToBigIntegerOrNull()` returns `null` on error
* `BigInteger.decodeFromAsn1ContentBytes()`
* `encodeToAsn1Primitive()` produces an ASN.1 primitive  `BigInteger`
* `encodeToAsn1ContentBytes()` producing the content bytes of an `Asn1Primitive` for `BigInteger`
