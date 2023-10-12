# 🔥🔥🔥KMP Crypto🔥🔥🔥

[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-brightgreen.svg?style=flat)](http://www.apache.org/licenses/LICENSE-2.0)
[![Kotlin](https://img.shields.io/badge/kotlin-multiplatform-orange.svg?logo=kotlin)](http://kotlinlang.org)
[![Kotlin](https://img.shields.io/badge/kotlin-1.9.10-blue.svg?logo=kotlin)](http://kotlinlang.org)
[![Java](https://img.shields.io/badge/java-11+-blue.svg?logo=OPENJDK)](https://www.oracle.com/java/technologies/downloads/#java11)
[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus/kmp-crypto)](https://mvnrepository.com/artifact/at.asitplus.kmp-crypto/)

## Kotlin Multiplatform Crypto/PKI library and ASN1 Parser + Encoder

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
**you can work with X509 Certificates, public keys, CSRs and arbitrary ASN.1 structures on iOS.**

**Do check our the full API docs [here]()**!

## Usage

This library was built for [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html). Currently, it targets
the JVM/Android and iOS.

This library consists of three modules, each of which is published on maven central:

| Name              | `datatypes`                                                                                                                  | `datatypes-jws`                                                                                                                                                                                                                       | `datatypes-cose`                                                                                                                                                                                                                    |
|-------------------|------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description       | Base module containing the public key class (`CryptoPublicKey`), algorithm identifiers, the ASN.1 parser, X.509 certificate. | JWS/JWE/JWT module containing JWS/E/T-specific data structures and extensions to convert from/to types contained in the base module. Includes all required kotlinx-serialization magic to allow for spec-compliant de-/serialization. | COSE module containing all COSE/CWT-specific data structures and extensions to convert from/to types contained in the base module. Includes all required kotlinx-serialization magic to allow for spec-compliant de-/serialization. |
| Maven Coordinates | `at.asitplus.crypto:datatypes`                                                                                               | `at.asitplus.crypto:datatypes-jws`                                                                                                                                                                                                    | `at.asitplus.crypto:datatypes-cose`                                                                                                                                                                                                 |

### Using it in your Projects

Simply declare the desired dependency to get going:

```kotlin 
implementation("at.asitplus.crypto:datatypes:$version")
```

Relevant classes like `CryptoPublicKey`, `X509Certificate`, `Pkcs10CertificationREquest`, etc. all
implement `Asn1Encodable` and their respective companions implement `Asn1Decodable`.
Which means that you can do things like parsing and examining certificates, creating CSRs, or transferring key material.

### Certificate Parsing

```kotlin
val cert = X509Certificate.derDecode(certBytes)

when (val pk = cert.publicKey) {
    is CryptoPublicKey.Ec -> println(
        "Certificate with serial no. ${
            cert.tbsCertificate.serialNumber.encodeToString(Base16)
        } contains an EC public key using curve ${pk.curve}"
    )

    is CryptoPublicKey.Rsa -> println(
        "Certificate with serial no. ${
            cert.tbsCertificate.serialNumber.encodeToString(Base16)
        } contains a ${pk.bits.number} bit RSA public key"
    )
}

println("The full certificate is:\n${Json { prettyPrint = true }.encodeToString(cert)}")

println("Re-encoding it produces the same bytes? ${cert.derEncoded contentEquals certBytes}")
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
        "value": "133352657075626C696B204F6573746572726569636820287665727472657465\n6E20647572636820424B4120756E6420424D445729"
      },
      {
        "type": "OU",
        "value": "130A542D556D676562756E67"
      },
      {
        "type": "CN",
        "value": "132B542D52657075626C696B2D4F657374657272656963682D41757468656E74\n6966697A696572756E672D3031"
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
        "value": "133352657075626C696B204F6573746572726569636820287665727472657465\n6E20647572636820424B4120756E6420424D445729"
      },
      {
        "type": "OU",
        "value": "130A542D556D676562756E67"
      },
      {
        "type": "CN",
        "value": "1340542D42696E64756E67732D5A6572746966696B61742D4157502D31653064\n3638306365646461343963653931333738646261393432653366343234666366\n3164"
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
val cryptoPublicKey = CryptoPublicKey.Ec.fromJcaKey(ecPublicKey /*from platform-specific code*/)

val commonName = "DefaultCryptoService"
val signatureAlgorithm = JwsAlgorithm.ES256


val tbsCsr = TbsCertificationRequest(
    version = 0,
    subjectName = listOf(DistinguishedName.CommonName(Asn1String.UTF8(commonName))),
    publicKey = cryptoPublicKey
)
val signed =  /* pass tbsCsr.derEncoded to platform code*/
val csr = CertificationRequest(tbsCsr, signatureAlgorithm, signed)

println(csr.derEncoded)
```

> [3081DA308181020100301F311D301B06035504030C1444656661756C7443727970746F536572766963653059301306072A8648CE3D020106082A8648CE3D03010703420004DF2444267805C50B29C4BFC2C726AF82F6BA8EBE1FACED277D475E12CF417816AE7218EC1C79844FEA89CDBA1E2DD4BD5039F76E4FBF8F999D548FD1151BC205A000300A06082A8648CE3D04030203480030450221008CB8D6ADAD4A594C75CD807D92807BF5EA72D8B10676E6B2FC1F813D9E1FD82F022037FD26AE0D2578E0266BCEABC83A35CE324CBFA6446411CBE24753E8B1F0852E](https://lapo.it/asn1js/#MIHaMIGBAgEAMB8xHTAbBgNVBAMMFERlZmF1bHRDcnlwdG9TZXJ2aWNlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3yREJngFxQspxL_Cxyavgva6jr4frO0nfUdeEs9BeBauchjsHHmET-qJzboeLdS9UDn3bk-_j5mdVI_RFRvCBaAAMAoGCCqGSM49BAMCA0gAMEUCIQCMuNatrUpZTHXNgH2SgHv16nLYsQZ25rL8H4E9nh_YLwIgN_0mrg0leOAma86ryDo1zjJMv6ZEZBHL4kdT6LHwhS4)

### Working with Generic ASN.1 Structures

The magic shown above is based on a from-scratch 100% KMP implementation of an ASN.1 encoder and parser.
To parse any DER-encoded ASN.1 structure, call `Asn1Element.parse(derBytes)`, which will result in exactly a single
`Asn1Element`.
It can be re-encoded (and yes, it is a true re-encoding, since the original bytes are discarded after decoding) by
accessing the lazily evaluated `.derEncoded` property.

**Note that decoding operations will throw exceptions if invalid data is provided!**

A parsed `Asn1Element` can either be a primitive (whose tag and value can be read) or a structure (like a set or
sequence) whose child
nodes can be processed as desired. Subclasses of `Asn1Element` reflect this:

* `Asn1Primitive`
* `Asn1Structure`
    * `Asn1Set`
    * `Asn1Sequence`

Any complex data structure (such as CSR, public key, certificate, …) implements `Asn1Encodable`, which means you can:

* encapsulate it into an ASN.1 Tree by calling `.encodeToTlv()`
* directly get a DER-encoded version through the `.derEncoded` lazily evaluated property

To also suport going the other way, the companion objects of these complex classes implement `Asn1Decodable`, which
allows for

* directly parsing DER-encoded byte arrays by calling `.derDecode(bytes)`
* processing an `Asn1Element` by calling `.fromTlv(src)`

#### Decoding Values

Various helper functions exist to facilitate decoging the values contained in `Asn1Primitives`, such as `decodeIn()`,
for example.
However, anything can be decoded and tagged at will. Therefore, a generic decoding function exists, which has the
following signature:

```kotlin
inline fun <reified T> Asn1Primitive.decode(tag: UByte, decode: (content: ByteArray) -> T) 
```

Check out [Asn1Reader.kt](datatypes/src/commonMain/kotlin/at/asitplus/crypto/datatypes/asn1/Asn1Reader.kt) for a full
list
of helper functions.

#### ASN1 DSL for Creating ASN.1 Structures

While it is perfectly possible to manually construct a hierarchy of `Asn1Element` objects, we provide a more convenient
DSL, which returns an `Asn1Structure`:

```kotlin
asn1Sequence {
  tagged(31u) {
    Asn1Primitive(BERTags.BOOLEAN, byteArrayOf(0x00))
  }
  set {
    sequence {
      setOf { //note: DER encoding enfoces sorting here, so the result switches those
        printableString { "World" }
        printableString { "Hello" }
      }
      set { //note: DER encoding enfoces sorting by tags, so the order changes in the ourput
        printableString { "World" }
        printableString { "Hello" }
        utf8String { "!!!" }
      }
    }
  }
  asn1null()

  oid { ObjectIdentifier("1.2.60873.543.65.2324.97") }

  utf8String { "Foo" }
  printableString { "Bar" }

  set {
    int { 3 }
    long { 123456789876543L }
    bool { false }
    bool { true }
  }
  sequence {
    asn1null()
    hexEncoded { "CAFEBABE" }
    hexEncoded { "BADDAD" }
    utcTime { instant }
  }
}
```
In accodance with DER-Encoding, this produces the following ASN.1 structure:

```
SEQUENCE {
   [1F] 010100
   SET {
      SEQUENCE {
         SET {
            PrintableString 'Hello'
            PrintableString 'World'
         }
         SET {
            UTF8String '!!!'
            PrintableString 'World'
            PrintableString 'Hello'
         }
      }
   }
   NULL 
   OBJECTIDENTIFIER 1.2.60873.543.65.2324.97
   UTF8String 'Foo'
   PrintableString 'Bar'
   SET {
      BOOLEAN FALSE
      BOOLEAN TRUE
      INTEGER 0x03 (3 decimal)
      INTEGER 0x7048861B0F3F
   }
   SEQUENCE {
      NULL 
      OBJECTIDENTIFIER 5.2
      OBJECTIDENTIFIER 4.26
      UTCTime '231011202808Z'
   }
}
```

## Limitations

As this library provides multiplatform data types to help interop with platform-specific crypto functionality, it does
not provide any functionality to carry out the actual cryptographic operations.
Also, it provides no abstractions for private keys, because those should never leave a system in the first place.

While a multiplatform crypto provider would be awesome, this sort fo things also needs a careful design phase before
even entertaining the thought of implementing such functionality. It therefore not planned at the time of this writing (
2023-10)

* While the ASN.1 perser will happily parse any valid **DER-encoded** ASN.1 structure you throw at it and the encoder
  write it back correctly too. (No, we don't care for BER, since we want to transport cryptographic material)
* Higher-level abstractions (such as `X509Certificate`) are too lenient in some aspects and
  too strict in others.
  For example: DSA-signed certificates will not parse to an instance of `X509Certificate`.
  At the same time, certificates containing the same extension multiple times will work fine, even though the violate
  the spec.
  This is irrelevant in practice, since platform-specific code will perform the actual cryptographic operations on these
  data structures and complain anyway, if something is off.
* We do need more comprehensive tests. Currently, me mostly focused on some delicate encoding aspects and tried to read
  and write-back certificates without mangling them.
* We don't yet know how compliant everything really is, but so far it could parse and re-encode every certificate we
  threw at it without braking anything
* Number of supported Algorithms is limited to the usual suspects (sorry, no Bernstein curves )-:)