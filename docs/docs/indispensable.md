![Indispensable](assets/core-dark-large.png#only-light)
![Signum](assets/core-light-large.png#only-dark)

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
* ObjectIdentifier Class with human-readable notation (e.g. 1.2.9.6245.3.72.13.4.7.6)
* 100% pure Kotlin BitSet
* Exposes Multibase Encoder/Decoder as an API dependency
  including [Matthew Nelson's smashing Base16, Base32, and Base64 encoders](https://github.com/05nelsonm/encoding)
* Generic ASN.1 abstractions to operate on and create arbitrary ASN.1 Data
* Serializability of all ASN.1 classes for debugging **AND ONLY FOR DEBUGGING!!!** *Seriously, do not try to deserialize
  ASN.1 classes through kotlinx.serialization! Use `decodeFromDer()` and its cousins!*
* **ASN.1 Parser and Encoder including a DSL to generate ASN.1 structures**

This last bit means that
you can work with X509 Certificates, public keys, CSRs and arbitrary ASN.1 structures on iOS.

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
    * `IosLegacyHomebrewAttesation` contains an attestation and an assertion, conforming to the emulated key attestation scheme
currently supported by warden.
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

#### ASN.1

The `asn1` package contains a 100% pure Kotlin (read: no platform dependencies) ASN.1 engine and data types:

* `Asn1Elements.kt` contains all ANS.1 element types
    * `Asn1Element` is an abstract, generic ASN.1 element. Has a tag and content. Can be DER-encoded
        * `Asn1Element.Tag` representing an ASN.1 tag. Contains user-friendly representations of:
            * Tag number
            * `CONSTRUCTED` bit
            * Tag Class
            * A set of predefined tag constants that are often encountered such as `INTEGER`, `OCTET STRING`, `BIT STRING`, etc…
      * `Asn1Primitive` is an ASN.1 element containing primitive data (string, byte strings, numbers, null, …)
      * `Asn1Structure` is a `CONSTRUCTED` ASN.1 type, containing zero or more ASN.1 child elements
        * `Asn1Sequence` has sequence semantics (order-preserving!)
        * `Asn1SequenceOf` has sequence semantics but allows only child nodes of the same tag
        * `Asn1Set` has set semantics, i.e. sorts all child nodes by tag in accordance with DER
        * `Asn1SetOf` has set semantics but allows only child nodes of the same tag

In addition, some convenience types are also present:

* `Asn1ExplicitlyTagged`, which is essentially a sequence, but with a user-defined `CONTEXT_SPECIFIC` tag
* `Asn1BitString`, wich is an ASN.1 primitive containing bit strings, which are not necessarily byte-aligned.
  Heavily relies on the included `BitSet` type to work its magic.
* `Asn1OctetString`, wich is often encountered in one of two flavours:
    * `Asn1PrimitiveOctetString` containing raw bytes
    * `Asn1EncapsulatingOctetString` containing any number of children. This is a structure, without the `CONSTRUCTED` bit set, using tag number `4`.
* `Asn1CustomStructure` representing a structure with a custom tag, that does not align with any predefined tag.
  Can be constructed to auto-sort children to conform with DER set semantics.
* `ObjectIdentifier` represents an ASN.1 OID
* `Asn1String` contains different String types (printable, UTF-8, numeric, …)
* `Asn1Time` maps from/to kotlinx-datetime `Instant`s and supports both UTC time and generalized time

The `asn1.encoding` package contains the ASN.1 builder DSL, as well as encoding and decoding functions
-- both for whole ASN.1 elements, as wells as for encoding/decoding primitive data types to/from DER-conforming byte arrays.
Most prominently, it comes with ASN.1 unsigned varint and minimum-length encoding of signed numbers.

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


## ASN.1 Engine

Relevant classes like `CryptoPublicKey`, `X509Certificate`, `Pkcs10CertificationRequest`, etc. all
implement `Asn1Encodable` and their respective companions implement `Asn1Decodable`.
This is an essential pattern, making the ASN.1 engine work the way it does.
We have opted against using kotlinx.serialization for maximum flexibility and more convenient debugging.  
The following section provides more details on the various patterns used for ASN.1 encoding and decoding.

### Generic Patterns
Recalling the classes in the `asn1` package described before already hints how ASN.1 elements are constructed.
In effect, it is just a nesting of those classes.
This works well for parsing and encoding but lacks higher-level semantics (in contrast to `X509CErtificate`, for example).

As mentioned before, classes like `CryptoPublicKey`, `X509Certificate`, and `ObjectIdentifier` all implement `Asn1Encodable`
while their companions implement `Asn1Decodable`.
These interfaces essentially provide a mapping between custom types and low-level TLV structures that can directly be encoded, conforming to DER.
This also means, a direct serialization of such custom types is valuable for debugging, but not for encoding.
**Hence, decoding a kotlinx.serialization output of those classes is unsupported.**


### Decoding
Decoding functions come in two categories: high-level functions, wich are used to map ASN.1 elements to types with enriched semantics
(such as certificates, public keys, etc.) and low-level ones, operating on the encoded values of TLV structures (i.e. decoding the _V_ in TLV).

#### High-Level

`Asn1Decodable` provides the following functions for decoding data:

* `doDecode()`, which is the only function that needs to be implemented by high-level types implementing `Asn1Encodable`.
  To provide a concrete example: This function needs to contain all parsing/decoding logic to construct a `CryptoPublicKey` from an `Asn1Sequence`.
* `verifyTag()` already implements optional tag assertion. The default implementation of  `decodeFromTlv()` (see below) calls this before invoking `doDecode()`.
* `decodeFromTlv()` takes an ASN.1 element and optional tag to assert, and returns a high-level type. Throws!
* `decodeFromTlvSafe()` does not throw, but returns a KmmResult, encapsulating the result of `decodeFromTlv()`
* `decodeFromTlvorNull()` does not throw, but returns null when decoding fails
* `decodeFromDer()` takes DER-encoded bytes, parses them into an ASN.1 element and calls `decodeFromTlv()`. Throws!
* `decodeFromDerSafe()` takes DER-encoded bytes. Does not throw, but returns a KmmResult, encapsulating the result of `decodeFromDer()`
* `decodeFromDerOrNull()` takes DER-encoded bytes. Does not throw, but returns null on decoding errors.

In addition, the companion of `Asn1Element` exposes the following functions:

* `parse()` parses a single ASN.1 element from the input and throws on error, or when additional input is left after parsing.
  This is helpful, to ensure that any given input contains a single, top-level ASN.1 element.
* `parseAll()` consumes all input and returns a list of parsed ASN.1 elements. Throws on error.
* `parseFirst()` comes in two flavours, both of which parse only a single, top-level ASN.1 element from the passed input
    * Variant 1 takes a `ByteIterator` and advances it until after the first parsed element.
    * Variant 2 takes a `ByteArray` and returns the first parses alement, as well as the remaining bytes (as `Pair<Asn1Element, ByteArray>`)
* `decodeFromDerHexString()` strips all whitespace before trying to decode an ASN.1 element from the provided hex string.
This function throws various exceptions on illegal input. Has the same semantics as `parse()`.

All of these return one or more `Asn1Element`s, which can then be passed to `decodeFromTlv()` if desired.
Low-level decoding functions deal with the actual decoding of payloads in TLV structures.

#### Low-Level

Some Low-level decoding functions are implemented as extension functions in `Asn1Primitive` for convenience (since CONSTRUCTED elements contain child nodes, but no raw data).
The base decoding function is called `decode()` and has the following signature:
```kotlin
fun <reified T> Asn1Primitive.decode(assertTag: ULong, transform: (content: ByteArray) -> T): T
```
An alternative exists, taking a `Tag` instead of an `Ulong`. in both cases a tag to assert and a user-defined transformation function is expected, which operates on
the content of the ASN.1 primitive. Moreover,  npn-throwing `decodeOrNull` variant is present.
In addition, the following self-describing shorthands are defined:

* `Asn1Primitive.decodeToBoolean()` throws on error
* `Asn1Primitive.decodeToBooleanOrNull()` returns `null` on error

* `Asn1Primitive.decodeToInt()` throws on error
* `Asn1Primitive.decodeToIntOrNull()` returns `null` on error

* `Asn1Primitive.decodeToLong()` throws on error
* `Asn1Primitive.decodeToLongOrNull()` returns `null` on error

* `Asn1Primitive.decodeToUInt()` throws on error
* `Asn1Primitive.decodeToUIntOrNull()` returns `null` on error

* `Asn1Primitive.decodeToULong()` throws on error
* `Asn1Primitive.decodeToULongOrNull()` returns `null` on error

* `Asn1Primitive.decodeToBigInteger()` throws on error
* `Asn1Primitive.decodeToBigIntegerOrNull()` returns `null` on error

* `Asn1Primitive.decodeToString()` throws on error
* `Asn1Primitive.decodeToStringOrNull()` returns `null` on error

* `Asn1Primitive.decodeToInstant()` throws on error
* `Asn1Primitive.decodeToInstantOrNull()` returns `null` on error

* `Asn1Primitive.readNull()` validates that the ASN.1 primitive is indeed an ASN.1 NULL. throws on error
* `Asn1Primitive.readNullOrNull()` validates that the ASN.1 primitive is indeed an ASN.1 NULL. returns `null` on error

In addition, an `asAsn1String()` conversion function exists that checks an ANS.1 primitive's tag and returns the correct `Asn1String` subtype (UTF-8, NUMERIC, BMP, …).
Manually working on DER-encoded payloads is also supported through the following extensions (each taking a `ByteArray` as input):

* `Int.decodeFromAsn1ContentBytes()`
* `UInt.decodeFromAsn1ContentBytes()`
* `Long.decodeFromAsn1ContentBytes()`
* `ULong.decodeFromAsn1ContentBytes()`
* `BigInteger.decodeFromAsn1ContentBytes()`
* `Boolean.decodeFromAsn1ContentBytes()`
* `String.decodeFromAsn1ContentBytes()`
* `Instant.decodeGeneralizedTimeFromAsn1ContentBytes()`
* `Instant.decodeUtcTimeFromAsn1ContentBytes()`

All of these functions throw an `Asn1Exception` when decoding fails.


### Encoding
Similarly to decoding function, encoding function also come as high-level and low-level ones.
The general idea is the same: `Asn1Encodable` should be implemented by any custom type that needs encoding to ANS.1,
while low-level encoding functions create the raw bytes contained in an `Asn1Primtive`.

#### High-Level
`Asn1Encodable` defines the following functions:

* `encodeToTlv()` is the only function that need to be implemented. It defines how user-defined types are converted to an ASN.1 element. Throws on error.
* `encodeToTlvOrNull()` is a non-throwing variant of the above, returning `null` on error.
* `encodeToTlvOrSafe()` encapsulates the encoding result into a `KmmResult`.
* `encodeToDer()` invokes `encodeToTlv().derEncoded` to produce a `ByteArray` conforming to DER. Throws on error.
* `encodeToDerOrNull()` is a non-throwing variant of the above, returning `null` on error.
* `encodeToDerSafe()` encapsulates the encoding result into a `KmmResult`.

`Asn1Element` and its subclasses come with the lazily-evaluated property `derEncoded` which produces a `ByteArray` conforming to DER.

#### Low-Level
Low-level encoding functions come in two flavours: On the one hand, functions to produce correctly tagged ASN.1 primitives exist.
These essentially delegate to the other kind of low-level encoding function, producing the content bytes of an `Asn1Primitive`.
Both kind of encoding functions follow a simple naming convention:

* `encodeToAsn1Primitive()` produces an ASN.1 primitive corresponding to the input.
This is implemented for `Int`, `UInt`, `Long`, `ULong`,  `BigInteger`, `Boolean`, and `String`
* `encodeToAsn1ContentBytes()` producing the content bytes of an `Asn1Primitive`.
This is implemented for `Int`, `UInt`, `Long`, `ULong`,  `BigInteger`, and `Boolean`. As for strings: An UTF-8 string is just its bytes.

In addition, some more specialized encoding functions exist for cases that are not as straight-forward:

* `ByteArray.encodeToAsn1OctetStringPrimitive()` produces an ASN.1 OCTET STRING containing the source bytes.
* `ByteArray.encodeToAsn1BitStringPrimitive()` produces an ASN.1 BIT STRING, prepending the source bytes with a single `0x00` byte.
* `ByteArray.encodeToAsn1BitStringContentBytes()` produces a `ByteArray` containing the source bytes, prepended with a single `0x00` byte.
* `Instant.encodeToAsn1UtcTimePrimitive()` produces an ASN.1 UTC TIME primitive
* `Instant.encodeToAsn1GeneralizedTimePrimitive()` produces an ASN.1 GENERALIZED TIME primitive

### Custom Tagging

This library comes with extensive tagging support and an expressive `Asn1Element.Tag` class.
ASN.1 knows EXPLICIT and IMPLICIT tags.
The former is simply a structure with SEQUENCE SEMANTICS and a user-defined CONSTRUCTED, CONTEXT_SPECIFIC tag, while the latter replaces an ASN.1 element's tag.

#### Explicit
To explicitly tag any number of elements, simply invoke `Asn1.ExplicitlyTagged`, set the desired tag and add the desired elements (see ASN.1 Builder DSL)
To create an explicit tag (to compare it to a parsed, explicitly tagged element, for example), just pass tag number (and optionally) tag class to `Asn1.ExplicitTag`.

#### Implicit

Implicit tagging is implemented differently. Any element can be implicitly tagged, after it was constructed, by invoking the
`withImplicitTag` infix function on it. There's, of course, also an option to override the tag class.
Creating an implicitly tagged UTF-8 String using the ASN.1 builder DSL with a custom tag class works as follows:

```kotlin
Asn1.Utf8String("Foo") withImplicitTag (0xCAFEuL withClass TagClass.PRIVATE)
```

It is also possible to unset the CONSTRUCTED bit from any ASN.1 structure or Tag by invoking the infix function `without` as follows:
```kotlin
Asn1.Sequence { +Asn1.Int(42) } withImplicitTag (0x5EUL without CONSTRUCTED)
```

!!! warning
    It is perfectly possible to use abuse implicit tagging in ways that produces UNIVERSAL tags that are reserved for well-defined types.
    If you really think you must create a faux ASN.1 NULL from an X.509 certificate go ahead, we dare you!
    Just blame the mess you created only on yourself and nobody else!


### ASN.1 Builder DSL
So far, custom high-level types and manually constructing low-level types was discussed.
When actually constructing ASN.1 structures, a far more streamlined and intuitive approach exists.
Signum's Indispensable module comes with a powerful, expressive ASN.1 builder DSL, including shorthand functions
covering CONSTRUCTED types and primitives.
Everything is grouped under a namespace object called `Asn1`. It not only streamlines the creation of complex ASN.1
structures, but also provides maximum flexibility. The following snippet showcases how it can be used in practice:

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

You can, of course, also create primitives, by directly invoking builder functions, like `Asn1.Int()` and use the resulting
ASN.1 primitive as-is.
!!! tip
    The builder also takes any `Asn1Encodable`, so you can also add an `X509Certificate`, or a `CryptoPublicKey` using
    the same concise syntax.  
    **Do checkout the [API docs](dokka/indispensable/at.asitplus.signum.indispensable.asn1.encoding/-asn1/index.html) for a full list of builder functions!**