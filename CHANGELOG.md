# Changelog

## 3.0

### 3.8.1 (Supreme 0.3.1)
* Hotfix for [KT-71650](https://youtrack.jetbrains.com/issue/KT-71650/Invalid-Objective-C-Header-in-XCFramework)
* Disables export of `Asn1Element.Tag` class to ObjC. Signum remains usable for KMP projects,
the Tag class just cannot be directly accessed from Swift and ObjC any more.

### 3.8.0 (Supreme 0.3.0) Breaking Changes Ahead!
* Completely revamped ASN.1 Tag Handling
  * Properly handle multi-byte tags
  * Introduce a new data structure `TLV.Tag` with an accompanying `TagClass` enum and a `constructed` flag to accurately represent arbitrary tags up to `ULong.MAX_VALUE`
  * Make all `tag` parameters `ULong` to reflect support for multi-byte tags
  * Remove `DERTags`
  * Revamp implicit tagging (there is still work to be done, but at least it supports CONSTRUCTED ASN.1 elements)
* Refactor `Int.Companion.decodeFromDer` -> `Int.Companion.decodeFromDerValue()`
* Refactor `Long.Companion.decodeFromDer` -> `Long.Companion.decodeFromDerValue()`
* Introduce `ULong.Companion.decodeFromDer` which can handle overlong inputs, as long as they start with a valid ULong encoding
* Changed return type of `Verifier::verify` from `KmmResult<Unit>` to `KmmResult<Success>`. Usage is unchanged.
* Add `ConfirmationClaim` to represent [Proof-of-Possesion Key Semantics for JWTs](https://datatracker.ietf.org/doc/html/rfc7800)
* Add claims to `JsonWebToken` to implement [Demonstrating Proof of Possession](https://datatracker.ietf.org/doc/html/rfc9449)
* Replace `JsonWebToken.confirmationKey` by `JsonWebToken.confirmationClaim`, the implementation was wrong
* Introduce `ULong.toAsn1VarInt()` to encode ULongs into ASN.1 unsigned VarInts (**not to be confused with
  multi^2_base's`UVarInt`!**)
* Introduce `decodeAsn1VarULong()` and `decodeAsn1VarUInt()` which can handle overlong inputs, as long as they start with a valid unsigned number encoding.
    * Comes in three ULong flavours:
        * `Iterator<Byte>.decodeAsn1VarULong()`
        * `Iterable<Byte>.decodeAsn1VarULong()`
        * `ByteArray.decodeAsn1VarULong()`
    * and three UInt flavours:
        * `Iterator<Byte>.decodeAsn1VarUInt()`
        * `Iterable<Byte>.decodeAsn1VarUInt()`
        * `ByteArray.decodeAsn1VarUInt()`
* Revamp implicit tagging
* Revamp `Asn1Element.parse()`, introducing new variants. This yields:
  * `Asn1Element.parse()` with the same semantics as before
  * `Asn1Element.parse()` alternative introduced, which takes a `ByteIterator` instead of a `ByteArray`
  * `Asn1Element.parseAll()` introduced, which consumes all bytes and returns a list of all ASN.1 elements (if parsing works)
    * Variant 1 takes a `ByteIterator`
    * Variant 2 takes a `ByteArray`
  * `Asn1Element.parseFirst()` introduced, which tries to only parse a single ASN.1 element from the input and leaves the rest untouched.
    * Variant 1 takes a `ByteIterator` and returns the element; the `ByteIterator` is advanced accordingly
    * Variant 2 takes a `ByteArray` and returns a `Pair` of `(element, remainingBytes)`
* More consistent low-level encoding and decoding function names:
  * `encodeToAsn1Primitive` to produce an `Asn1Primitive` that can directly be DER-encoded
  * `encodeToAsn1ContentBytes` to produce the content bytes of a TLV primitive (the _V_ in TLV)
  * `decodeToXXX` to be invoked on an `Asn1Primitive` to decode a DER-encoded primitive into the target type
  * `decodeFromAsn1ContentBytes` to be invoked on the companion of the target type to decode the content bytes of a TLV primitive (the _V_ in TLV)
* Update conventions -> Coroutines 1.9.0
* replace `runCatching` with `catching` to be extra-safe

### 3.7.0 (Supreme 0.2.0)
* Remove Swift verifier logic to obtain a general speed-up
* Implement supreme signing capabilities
* Introduce Attestation Data Structure
* Dependency Updates:
  * Kotlin 2.0.20
  * kotlinx.serialization 1.7.2 stable (bye, bye unofficial snapshot dependency!)
  * kotlinx-datetime 0.6.1

### 3.6.1
* Externalise `UVarInt` to  multibase

### 3.6.0
* Rebranding to Signum
  * maven coordinates: `at.asitplus.signum:$module`
  * modules
    * datatypes -> indispensable
    * datatypes-jws -> indispensable-josef
    * datatypes-cose -> indispensable-cosef
    * provider -> supreme
  * package renames
  * `crypto` -> `signum`
  * `datatypes` -> `indispensable`
  * `jws` -> `josef`
  * `cose` -> `cosef`
  * `provider` -> `supreme`

### 3.5.1

** Fixes **

* Publish provider pre-release to maven central

** Changes **

* Depend on newer conventions, which don't pull serialization snapshots in:
    * `datatypes`, `datatypes-jws`, and `provider` depend on stable serialization **WITHOUT COSE SUPPORT**
    *  `datatypes-cose` pulls in latest 1.8.0 serialization SNAPSHOT from upstream
* `ByteStringWrapper` is not part of upstream snapshot cose serialization anymore,
  but implemented as part of `datatypes-cose` in package `at.asitplus.crypto.datatypes.cose.io`


### 3.5.0

**Fixes**
* Fix calculation of JWK thumbprints according to [RFC7638](https://www.rfc-editor.org/rfc/rfc7638.html)

**Changes**
* Add `provider` module that actually implements cryptography! (Currently in preview, signature verification only)
* Add `COSE_Key` header to `CoseHeader`, defined in OpenID for Verifiable Credential Issuance draft 13
* Fix serialization of COSE signature structures
* Refactor `JsonWebKey`:
    * Remove `identifier`, please use `keyId` or `jwkThumbprint` directly
    * Add `equalsCryptographically()` to compare two keys by their cryptographic properties only
* Externalise multibase implementation

### 3.2.2
* KmmResult 1.7.0
* Bignum 0.3.10 stable
* okio 3.9.0

### 3.2.1

**Fixes**
* Correct serialization of COSE signature structures

### 3.2.0

* Kotlin 2.0
* Gradle 8.8
* Bouncy Castle 1.78.1
* Kotest 5.9.1
* Coroutines 1.8.1
* Serialization 1.7.1-SNAPSHOT
* KmmResult 1.6.2

**Fixes**
* Move `curve` from `CryptoAlgorithm` to `JwsAlgorithm`
* Don't assume curve information for the X.509 signature when, in fact, none exists
    * `CryptoSignature`s in X.509 are now indefinite length

**Changes**
* Always DID-encode keys in compressed form (but keep decoding support)
* Rename `CryptoAlgorithm` to `X509SignatureAlgorithm` to better describe what it is
    * Rename `toCryptoAlgorithm` to `toX509SignatureAlgorithm` accordingly
* Rework CryptoSignature to two-dimensional interface:
    * CryptoSignature <- {EC <- {IndefiniteLength, DefiniteLength}, RsaOrHmac}
    * CryptoSignature <- {RawByteEncodable <- {EC.DefiniteLength, RsaOrHmac}, NotRawByteEncodable <- EC.IndefiniteLength}

### 3.1.0

**Fixes**
* Standardize class names: `Ec` -> `EC` everywhere
* Fix an edge case where very small `r`/`s` in `CryptoSignature.EC` would be corrupted
* Remove bogus ASN.1 encoding from JWS Algorithms
    * `CryptoSignature.EC` now requires specification of a curve or size when reading raw bytes

**Features**
* Support ASN.1 encoding/decoding for `BigInteger`
* Expose `generator`, `order` and `cofactor` of `ECCurve`
* Extend list of values in `JweAlgorithm` and `JweEncryption`
* Extend properties in `JweHeader`
* Extend properties in `JwsHeader`
* **BREAKING CHANGE:** Completely revamp the ASN.1 builder DSL
    * explicitly require `+` to add some ASN.1 element to a builder
    * Make convenience functions like `Bool(<boolean value>)`work stand-alone
* Introduce common interface `JsonWebAlgorithm` for Jw{s,e}Algorithm
* JsonWebKey Changes:
    * do not generate kid when there is none and allow removing it
    * reference `JsonWebAlgorithm` instead of `JwsAlgorithm`
    * add `.didEncoded`, which may return null, if encoding fails
* add `.curve` to EC CryptoAlgorithms
* Change JweAlgorithm to sealed class to support unknown algorithms
* Add generic `ECPoint` class
* Implement elliptic-curve arithmetic


### 3.0.0

**Fixes**
* Restructure and fix `RelativeDistinguishedName`. **THIS IS A BREAKING CHANGE**
* Fix `Asn1Time` not truncating to seconds
* Fix parsing of CryptoSignature when decoding Certificates
* Remove bogus `serialize()` function from `CryptoSignature`  **THIS IS A BREAKING CHANGE**


**Features**
* Wrap exceptions during deserialization in `KmmResult`, i.e. changing all `deserialize()` methods in companion objects  **THIS IS A BREAKING CHANGE**
* Move class `JweDecrypted` from package `at.asitplus.wallet.lib.jws` to `at.asitplus.crypto.datatypes.jws`  **THIS IS A BREAKING CHANGE**
* Support more JWE algorithms, e.g. AES
* Add `header` to constructor parameters of `JweEncrypted`
* Extend properties of `JsonWebKey`
* Introduce `CertificateChain` typealias with `.leaf` and `.root` convenience properties
* Use `CertificateChain` inside `JwsHeader` instead of `Array<ByteArray>'
* Use `CertificateChain` inside `JsonWebKey` instead of `Array<ByteArray>'

* SubjectAltNames and IssuerAltNames:
    * Perform some structural validations on SAN and IAN
    * Expose `TbsCertificate.issuerAltNames` and `TbsCertificte.subjectAltnames`, which contain (somewhat) parsed
      `AlternativeNames` structures for easy access to `dnsName`. `iPAddress`, etc.


---

## 1.0

### 1.0.0
 First public release
 
## 2.0

### 2.0.0
 * JWS Support
 * Bugfixes and streamlining all over the place
 * Proper BIT STRING
 * BitSet (100% Kotlin BitSet implementation)
 * Recursively parsing (and encapsulating) ASN.1 structures in OCTET Strings
 * Initial pretty-printing of ASN.1 Strucutres
 * Massive ASN.1 builder DSL streamlining
 * More convenient explicit tagging


### 2.1.0
* Kotlin 1.9.20
* COSE Support
* Full RSA and HMAC Support
* New interface `Asn1OctetString` to unify both ASN.1 OCTET STREAM classes
* Fix broken `content` property of `Asn1EncapsulatingOctetString`
* Refactor `.derEncoded` property of `Asn1Encodable` interface to function `.encodeToDer()`
* Consistent exception handling behaviour
  * Throw new type `Asn1Exception` for ASN.1-related errors
  * Throw `IllegalArgumentException` for input-related errors
  * Add `xxxOrNull()` functions for all encoding/decoding/parsing functions
  * Add `xxxSafe()` functions to encapsulate encoding/decoding in `KmmResult`
  * Return `KmmResult` for conversions between different key representations ( i.e. `CryptoPublicKey`, `CoseKey` and `JsonWebKey`) 

### 2.2.0
* Dependency Updates
  * KmmResult 1.5.4
* Refactor `MultiBaseHelper` to only handle conversion
* Change `JwsHeader.publicKey` from JsonWebKey to CryptoPublicKey
* Remove `SignatureValueLength` parameters from JWS & COSE Algorithm Enum class
* Remove deprecated functions
* Rename `Jws` classes
  * New `CryptoAlgorithm` class
  * New `CryptoSignature` class for easy Asn1 - RawByteArray conversion
* Rename function in file `JcaExtensions.kt` from `.toPublicKey` to `.toJcaPublicKey` to reflect connection to JVM
* Remove VcLib-specific constants

#### 2.2.1
* Update conventions
  * Rename CBOR annotations
  * Target Java 17

### 2.3.0
* Change `CryptoPublicKey.toJsonWebKey()` return type from `KmmResult<JsonWebKey>` to `JsonWebKey`
* Add `CryptoSignature.parseFromJca` function
* Refactor `CryptoPublicKey.keyID` to `CryptoPublicKey.didEncoded` to better reflect what it actually is
* Rename `CryptoPublicKey.fromKeyId` to `CryptoPublicKey.fromDid`

### 2.4.0
* Add Support for EC Point compression
* Add Support for full Cose-Key Spec
* Correct Multibase Encoding
* Change `DID:KEY` encoding to Base58_BTC to comply with draft
* Add Multibase Encoder/Decoder
* Add UVarInt datatype (63 bit max)
* Remove MultibaseHelper
* Finally make `CoseKey`'s EC Point compression play nicely with kotlinx.serialization
* Rename `CoseKey.fromKeyId` to `CoseKey.fromDid`
* Rename `JsonWebKey.fromKeyId` to `JsonWebKey.fromDid`

### 2.5.0
* Parse more certificates from `x5c` in JWS headers
* Kotlin 1.9.23 thanks to updated conventions
* Generate `KnownOIDs` using [KotlinPoet](https://square.github.io/kotlinpoet/)
* Work around KT-65315 thanks to updated conventions
* BigNum as API dependency and iOS export (seems nonsensical,
  but is somehow required when using this inside a compose multiplatform app)
* Rename `BERTags.NULL` to `BERTags.ASN1_NULL` to fix broken ObjC export 

### 2.6.0
 * Pull in `JsonWebKeySet` from `vclib`
 * Implement JWK Set Url (`jku`) in JWS headers
 * Implement Attestation JWT (`jwt`) in JWS headers
 * Implement Confirmation keys (`cnf`) in JWT
 * Implement `CborWebToken` (RFC 8392)
 * Boolean ASN.1 decoding helper function
 * Certificate to/from JCA certificate conversion functions
