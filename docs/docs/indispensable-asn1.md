![Indispensable ASN.1](assets/asn1-dark-large.png#only-light)
![Indispensable ASN.1](assets/asn1-light-large.png#only-dark)

[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus.signum/indispensable-asn1?label=maven-central)](https://mvnrepository.com/artifact/at.asitplus.signum.indispensable/)

# Indispensable ASN.1 Engine

This [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library provides the most sophisticated KMP ASN.1 engine in the known universe. kotlinx-* dependencies aside, it only depends only on [KmmResult](https://github.com/a-sit-plus/kmmresult) for extra-smooth iOS interop.
It features:

* **ASN.1 Parser and Encoder including a DSL to generate ASN.1 structures**
* ObjectIdentifier Class with human-readable notation (e.g. 1.2.9.6245.3.72.13.4.7.6)
* ASN.1 Integer (variable length integer)
* 100% pure Kotlin BitSet
* Generic ASN.1 abstractions to operate on and create arbitrary ASN.1 Data
* Support for all targets but wasm/WASI (due to Kotest not supporting it)

This in short, you can work with arbitrary ASN.1 structures anywhere!

!!! tip
    **Do check out the full API docs [here](dokka/indispensable-asn1/index.html)**!

## Using it in your Projects

This library was built for [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html). Currently, it supports all KMP targets.

Simply declare the desired dependency to get going:

```kotlin 
implementation("at.asitplus.signum:indispensable-asn1:$version")
```

## Structure and Class Overview
As the name _Indispensable ASN.1_ implies, this module is indispensable, if you work with ASN.1 structures.

### Package Organisation

The `asn1` package contains a 100% pure Kotlin (read: no platform dependencies) ASN.1 engine and data types:

* `Asn1Elements.kt` contains all ASN.1 element types
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
-- both for whole ASN.1 elements, as well as for encoding/decoding primitive data types to/from DER-conforming byte arrays.
Most prominently, it comes with ASN.1 unsigned varint and minimum-length encoding of signed numbers.

## ASN.1 Core

The ASN.1 engine allows decoding and encoding arbitrary structures from/to `ByteArray`s, as well as kotlinx.io `Source` and `Sink`.

Relevant _Indispensable_ classes like `CryptoPublicKey`, `X509Certificate`, `Pkcs10CertificationRequest`, etc. all
implement `Asn1Encodable` and their respective companions implement `Asn1Decodable`.
This is an essential pattern, making the ASN.1 engine work the way it does.
We have opted against using kotlinx.serialization for maximum flexibility and more convenient debugging.  
The following section provides more details on the various patterns used for ASN.1 encoding and decoding.

### Generic Patterns
Recalling the classes in the `asn1` package described before already hints how ASN.1 elements are constructed.
In effect, it is just a nesting of those classes.
This works well for parsing and encoding but lacks higher-level semantics (in contrast to `X509Certificate` from the _Indispensable_ module, for example).


### Decoding
Decoding functions come in two categories: high-level functions, wich are used to map ASN.1 elements to types with enriched semantics
(such as certificates, public keys, etc.) and low-level ones, operating on the encoded values of TLV structures (i.e. decoding the _V_ in TLV).
Hence, a typical decoding pipeline looks as follows:



| Encoded Bytes    |      ––––&rarr;       |                          ASN.1 Element                           |             ––––&rarr;             | `Asn1Encodable` rich type          |
|------------------|:---------------------:|:----------------------------------------------------------------:|:----------------------------------:|------------------------------------|
| `06052B81040022` | `Asn1Element.parse()` |  `Primitive(tag=6 (=06), length=5, overallLength=7) 2B81040022`  | `ObjectIdentifier.decodeFromTlv()` | `ObjectIdentifier("1.3.132.0.34")` |


#### High-Level

`Asn1Decodable` provides the following functions for decoding data:

* `doDecode()`, which is the only function that needs to be implemented by high-level types implementing `Asn1Encodable`.
  To provide a concrete example: This function needs to contain all parsing/decoding logic to construct a `CryptoPublicKey` from an `Asn1Sequence`,
  as demonstrated in the [_Indispensable_ source code](https://github.com/a-sit-plus/signum/blob/main/indispensable/src/commonMain/kotlin/at/asitplus/signum/indispensable/CryptoPublicKey.kt#L109).
* `verifyTag()` already implements optional tag assertion. The default implementation of  `decodeFromTlv()` (see below) calls this before invoking `doDecode()`.
* `decodeFromTlv()` takes an ASN.1 element and optional tag to assert, and returns a high-level type. Throws!
* `decodeFromTlvSafe()` does not throw, but returns a KmmResult, encapsulating the result of `decodeFromTlv()`
* `decodeFromTlvorNull()` does not throw, but returns null when decoding fails
* `decodeFromDer()` takes DER-encoded bytes, parses them into an ASN.1 element and calls `decodeFromTlv()`. Throws!
* `decodeFromDerSafe()` takes DER-encoded bytes. Does not throw, but returns a KmmResult, encapsulating the result of `decodeFromDer()`
* `decodeFromDerOrNull()` takes DER-encoded bytes. Does not throw, but returns null on decoding errors.

In addition, the companion of `Asn1Element` exposes the following functions:

* `parse()` parses a single ASN.1 element from the input and throws on error, or when additional input is left after parsing.
  This ensures that the input contains a single, top-level ASN.1 element.
* `parseAll()` consumes all input and returns a list of parsed ASN.1 elements. Throws on error.
* `Source.readAsn1Element()` decodes a single ASN.1 element (can be a structure or a primitive) from a kotlix.io Source.
* `parseFirst()` comes in two flavours, both of which parse only a single, top-level ASN.1 element from the passed input
    * Variant 1 takes a `Source` and advances it until after the first parsed element.
    * Variant 2 takes a `ByteArray` and returns the first parses element, as well as the remaining bytes (as `Pair<Asn1Element, ByteArray>`)
* `decodeFromDerHexString()` strips all whitespace before trying to decode an ASN.1 element from the provided hex string.
This function throws various exceptions on illegal input. Has the same semantics as `parse()`.

All of these return one or more `Asn1Element`s, which can then be passed to `decodeFromTlv()` if desired.
Low-level decoding functions deal with the actual decoding of payloads in TLV structures.

#### Low-Level

Some low-level decoding functions are implemented as extension functions in `Asn1Primitive` for convenience (since CONSTRUCTED elements contain child nodes, but no raw data).
The base decoding function is called `decode()` and has the following signature:
```kotlin
fun <reified T> Asn1Primitive.decode(assertTag: ULong, transform: (content: ByteArray) -> T): T
```
An alternative exists, taking a `Tag` instead of an `Ulong`. in both cases a tag to assert and a user-defined transformation function is expected, which operates on
the content of the ASN.1 primitive. Moreover, a non-throwing `decodeOrNull` variant is present.
In addition, the following self-describing shorthands are defined:

| Function                                    | Description                                                                         |
|---------------------------------------------|-------------------------------------------------------------------------------------|
| `Asn1Primitive.decodeToBoolean()`           | throws                                                                              |
| `Asn1Primitive.decodeToBooleanOrNull()`     | returns `null` on error                                                             |
|                                             |                                                                                     |
| `Asn1Primitive.decodeToInt()`               | throws                                                                              |
| `Asn1Primitive.decodeToIntOrNull()`         | returns `null` on error                                                             |
|                                             |                                                                                     |
| `Asn1Primitive.decodeToLong()`              | throws                                                                              |
| `Asn1Primitive.decodeToLongOrNull()`        | returns `null` on error                                                             |
|                                             |                                                                                     |
| `Asn1Primitive.decodeToUInt()`              | throws                                                                              |
| `Asn1Primitive.decodeToUIntOrNull()`        | returns `null` on error                                                             |
|                                             |                                                                                     |
| `Asn1Primitive.decodeToULong()`             | throws                                                                              |
| `Asn1Primitive.decodeToULongOrNull()`       | returns `null` on error                                                             |
|                                             |                                                                                     | 
| `Asn1Primitive.decodeToDouble()`            | throws                                                                              |
| `Asn1Primitive.decodeToDoubleOrNull()`      | returns `null` on error                                                             |
|                                             |                                                                                     | 
| `Asn1Primitive.decodeToFloat()`             | throws                                                                              |
| `Asn1Primitive.decodeToFloatOrNull()`       | returns `null` on error                                                             |
|                                             |                                                                                     |
| `Asn1Primitive.decodeToAsn1Integer()`       | throws                                                                              |
| `Asn1Primitive.decodeToAsn1IntegerOrNull()` | returns `null` on error                                                             |
|                                             |                                                                                     |
| `Asn1Primitive.decodeToAsn1Real()`          | throws                                                                              |
| `Asn1Primitive.decodeToAsn1RealOrNull()`    | returns `null` on error                                                             |
|                                             |                                                                                     |
| `Asn1Primitive.decodeToEnumOrdinal()`       | throws                                                                              |
| `Asn1Primitive.decodeToEnumOrdinalOrNull()` | returns `null` on error                                                             |
|                                             |                                                                                     |
| `Asn1Primitive.decodeToEnum()`              | throws                                                                              |
| `Asn1Primitive.decodeToEnumOrNull()`        | returns `null` on error                                                             |
|                                             |                                                                                     |
| `Asn1Primitive.decodeToEnumOrdinal()`       | throws                                                                              |
| `Asn1Primitive.decodeToEnumOrdinalOrNull()` | returns `null` on error                                                             |
|                                             |                                                                                     |
| `Asn1Primitive.decodeToString()`            | throws                                                                              |
| `Asn1Primitive.decodeToStringOrNull()`      | returns `null` on error                                                             |
|                                             |                                                                                     |
| `Asn1Primitive.decodeToInstant()`           | throws                                                                              |
| `Asn1Primitive.decodeToInstantOrNull()`     | returns `null` on error                                                             |
|                                             |                                                                                     |
| `Asn1Primitive.readNull()`                  | validates that the ASN.1 primitive is indeed an ASN.1 NULL. throws on error         |
| `Asn1Primitive.readNullOrNull()`            | validates that the ASN.1 primitive is indeed an ASN.1 NULL. returns `null` on error |

In addition, an `asAsn1String()` conversion function exists that checks an ASN.1 primitive's tag and returns the correct `Asn1String` subtype (UTF-8, NUMERIC, BMP, …).
Manually working on DER-encoded payloads is also supported through the following extensions (each taking a `ByteArray` as input):

* `Int.decodeFromAsn1ContentBytes()`
* `UInt.decodeFromAsn1ContentBytes()`
* `Long.decodeFromAsn1ContentBytes()`
* `ULong.decodeFromAsn1ContentBytes()`
* `Double.decodeFromAsn1ContentBytes()`
* `Float.decodeFromAsn1ContentBytes()`
* `Asn1Integer.decodeFromAsn1ContentBytes()`
* `Asn1Real.decodeFromAsn1ContentBytes()`
* `Boolean.decodeFromAsn1ContentBytes()`
* `String.decodeFromAsn1ContentBytes()`
* `Instant.decodeGeneralizedTimeFromAsn1ContentBytes()`
* `Instant.decodeUtcTimeFromAsn1ContentBytes()`

All of these functions throw an `Asn1Exception` when decoding fails.

Moreover, a generic tag assertion function is present on `Asn1Element`, which throws an `Asn1TagMisMatchException` on error
and returns the tag-asserted element on success:

* `Asn1Element.assertTag()` takes either an `Asn1Element.Tag` or an `ULong` tag number

### Encoding
Similarly to decoding function, encoding function also come as high-level and low-level ones.
The general idea is the same: `Asn1Encodable` should be implemented by any custom type that needs encoding to ASN.1,
while low-level encoding functions create the raw bytes contained in an `Asn1Primitive`.
Hence, a typical encoding pipeline looks as follows:

| `Asn1Encodable` rich type           |     ––––&rarr;      |                          ASN.1 Element                           |        ––––&rarr;        | Encoded Bytes    |
|-------------------------------------|:-------------------:|:----------------------------------------------------------------:|:------------------------:|------------------|
| `ObjectIdentifier("1.3.132.0.34")`  | `oid.encodeToTlv()` |  `Primitive(tag=6 (=06), length=5, overallLength=7) 2B81040022`  | `Asn1Element.derEncoded` | `06052B81040022` |


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
Low-level encoding functions come in two flavours:
On the one hand, functions exist to produce correctly tagged ASN.1 primitives exist, including tag, length, and the encoded value.
On the other hand, there are functions responsible for producing only the content bytes of an `Asn1Primitive`. The first kind of functions rely on this second kind to encode values.
Both kind of encoding functions follow a simple naming convention:

* `encodeToAsn1Primitive()` produces an ASN.1 primitive corresponding to the input.
This is implemented for `Int`, `UInt`, `Long`, `ULong`, `Double`,  `Float`, `Asn1Integer`, `Asn1Real`, `Boolean`, `Enum` and `String`
* `encodeToAsn1ContentBytes()` producing the content bytes of an `Asn1Primitive`.
This is implemented for `Int`, `UInt`, `Long`, `ULong`, `Double`, `Float`, `Asn1Integer`, `Asn1Real`, `Boolean`, and `Enum`.
* As for strings: An UTF-8 string is just its bytes.

In addition, some more specialized encoding functions exist for cases that are not as straight-forward:

* `ByteArray.encodeToAsn1OctetStringPrimitive()` produces an ASN.1 OCTET STRING containing the source bytes.
* `ByteArray.encodeToAsn1BitStringPrimitive()` produces an ASN.1 BIT STRING, prepending the source bytes with a single `0x00` byte.
* `ByteArray.encodeToAsn1BitStringContentBytes()` produces a `ByteArray` containing the source bytes, prepended with a single `0x00` byte.
* `Instant.encodeToAsn1UtcTimePrimitive()` produces an ASN.1 UTC TIME primitive
* `Instant.encodeToAsn1GeneralizedTimePrimitive()` produces an ASN.1 GENERALIZED TIME primitive

### Custom Tagging

This library comes with extensive tagging support and an expressive `Asn1Element.Tag` class.
ASN.1 knows EXPLICIT and IMPLICIT tags.
The former is simply a structure with SEQUENCE semantics and a user-defined CONSTRUCTED, CONTEXT_SPECIFIC tag, while the latter replaces an ASN.1 element's tag.

#### Explicit
To explicitly tag any number of elements, simply invoke `Asn1.ExplicitlyTagged`, set the desired tag and add the desired elements using the ASN.1 builder DSL:

```kotlin
ExplicitlyTagged(1uL) {
  +Asn1.Bool(false)
}
```

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


### Object Identifiers
Signum's _Indispensable ASN.1_ engine comes with an expressive, convenient, and efficient ASN.1 `ObjectIdentifier` class.
It can be constructed by either parsing a `ByteArray` containing ASN.1-encoded representation of an OID,
or constructing it from a humanly-readable string representation (`"1.2.96"`, `"1 2 96"`).
In addition, it is possible to pass OID node components as either `UInt` or decimal string representation to construct an OID:
`ObjectIdentifier(1u, 3u, 6u, 1u)`, `ObjectIdentifier("1.2.3.234567898765434567")`.

The OID class exposes a `nodes` property, corresponding to the individual components that make up an OID node for convenience,
as well as a `bytes` property, corresponding to its ASN.1-encoded `ByteArray` representation.  
One peculiar characteristic of the `ObjectIdentifier` class is that both `nodes` and `bytes` properties are lazily evaluated.
This means that if the OID was constructed from raw bytes, accessing `bytes` is a NOOP, but operating on `nodes` is initially
quite expensive, since the bytes have yet to be parsed.
Conversely, if an OID was constructed from a string, accessing `bytes` is slow.
If, however, an OID was constructed from `UInt` components, those are eagerly encoded into bytes and the `nodes` property
is not immediately initialized.  
Finally, it is possible to directly construct an OID from a `Uuid`, which directly constructs an OID in Subtree `2.35`, which
takes the same path as evaluating a String, but with some shortcuts.

This lazy-evaluation behaviour boils down to performance: Only very rarely, will you want to create an OID with components exceeding `UInt.MAX_VALUE`,
but you will almost certainly want to encode a OID you created to ASN.1.
On the other hand, parsing an OID from ASN.1-encoded bytes and re-encoding it are both close to a NOOP (object creation aside).

### ASN.1 Integer
The ASN.1 engine provides its own bigint-like class, `Asn1Integer`. It is capable of encoding arbitrary length signed integers
to write and read them from ASN.1 structures.
It natively supports encoding from/to a two's complement `ByteArray`, and sign + magnitude representation,
making it interoperable with [Kotlin MP BigNum](https://github.com/ionspin/kotlin-multiplatform-bignum)
and JVM's `BigInteger`.

### ASN.1 Real
The ASN.1 engine provides its variable-precision floating-point class, `Asn1Real`. It is capable of encoding arbitrary
length signed floating point numbers to write and read them from ASN.1 structures.
It natively supports encoding from/to Kotlin's built-in `Float` and `Double`.

Encoding and Decoding a Kotlin double-precision floating point number will result in the same `Double`.
**However**, an ASN.1 REAL can use a higher precision than 64 bit. Hence, decoding arbitrary ASN.1 REAL numbers to `Double`
can result in a loss of precision.
When decoding to `Float`, this is even more likely to happen.
To avoid this, simply keep the `Asn1Real` as-is.

### ASN.1 Builder DSL
So far, custom high-level types and manually constructing low-level types was discussed.
When actually constructing ASN.1 structures, a far more streamlined and intuitive approach exists.
Signum's Indispensable ASN.1 engine comes with a powerful, expressive ASN.1 builder DSL, including shorthand functions
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
    **Do checkout the [API docs](dokka/indispensable-asn1/at.asitplus.signum.indispensable.asn1.encoding/-asn1/index.html) for a full list of builder functions!**