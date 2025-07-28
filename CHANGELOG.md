# Changelog

## 3.0

### NEXT
* Kotest 6.0.0.M6
* Remove Kotest Workarounds

### 3.17.0 (Supreme 0.9.0)
* **KDF Support**
    * PBKDF2
    * HKDF
    * scrypt
* X.509 Revamp
    * Introduce `X509SignatureAlgorithmDescription`, which is the OID + params pair that identifies a `X509SignatureAlgorithm`
      * Instances of `X509SignatureAlgorithm` represent algorithms that are known to Signum
      * Test `.isSupported()` or `.requireSupported()` (with contract smart-cast support)
    * `X509Certificate` and `Pkcs10CertificationRequest` now use `X509SignatureAlgorithmDescription` to represent a non-validated signature algorithm
    * Refactor `X509Certificate` and `TbsCertificate` to store the raw signature as `Asn1Primitive` and the raw public key as `Asn1Sequence` enabling support for certificates with unsupported signature algorithms
        * Use the new KmmResult-returning `decodedSignature` and `decodedPublicKey` members to replace `publicKey` and `signature`, respectively.
        * The old `publicKey` and `signature` are being deprecated.
    * Refactor `Pkcs10CertificationRequest` to store the raw signature as `Asn1Primitive` enabling unsupported signature algorithms
        * Use the new KmmResult-returning `decodedSignature` and `decodedPublicKey`, respectively.
* **RSA encryption** using in-memory keys (no hardware-backed key management yet)
* Add structured iterator-based decoding of `Asn1Structure`. `Asn1Structure` now implements `Iterable<Asn1Element>`:
    * Deprecate child accessors in `Asn1Structure` with deprecation level ERROR:
        * `nextChild()`
        * `nextChildOrNull()`
        * `hasMoreChildren()`
        * `peek()`
    * Add inner `Iterator` for child accesses
        * Add `Iterator.reversed()` method for getting a new iterator from an existing one, but with reversed direction, **keeping the current index**
        * Add `Asn1Structure.reverseIterator()` to get a reversed iterator right away, to iterate over all child elements in reverse.
    * Add `decodeAs()` for decoding ASN.1 structures via iterator-based lambda, moved trailing data check from `decodeFromTlv()` to `decodeAs()`
    * Refactor `doDecode()` implementations in `Asn1Structure` subclasses to use the new `decodeAs()` iterator-based API instead of deprecated child access methods.
* Add `SpecializedSymmetricEncryptionAlgorithm`
    * This allows `randomKey()` etc to operate on COSE/JWE algorithms
* Move constants of `KnownOIDs` into a discrete module `indispensable-oids` as extensions on the `KnownOIDs` object
    * **→ update your imports!**
* ASN.1 polishing:
    * rename `Asn1Element.length` property to `Asn1Element.contentLength` (and add a delegate with the old name and deprecation annotation to the new property)
    * Add missing `Asn1.Real` shorthand to the ASN.1 builder
    * Add `Asn1Null` constant
    * Add human-readable ASN.1 element `prettyPrint()` method
    * Make `Asn1OctetString` interface sealed
* Strippable `KnownOIDs`
    * Move `KnownOIDs` into a discrete module `indispensable-oids`
* OID descriptions:
    * `KnownOIDs` now implements `MutableMap<ObjectIdentifier, String>` to store and look up descriptions of Object Identifiers 
    * OIDs can hence be described using `KnownOIDs[theExpressionistsOid] = "Edvard Munch"`
    * OID descriptions are exposed in accordance with the map interface: `KnownOIDs[theExpressionistsOid]` will yield `"Edvard Munch"` if this description was added prior.
    * All OIDs present in `KnownOIDs` shipped with the `indispensable-oids` module come with a description. To actually add them to all known descriptions, call `KnownOIDs.describeAll()` once.
* Deprecate `serialize()` and `deserialize()` methods in COSE+ JOSE data classes
* Clean up some function signatures:
    * `SymmetricKey.toJsonWebKey` now returns `KmmResult`
    * `SymmetricEncryptionAlgorithm.toJweKwAlgorithm` now returns `KmmResult`
    * `SymmetricEncryptionAlgorithm.toJweEncryptionAlgorithm` removed
* In `JwsHeader` add property `vcTypeMetadata` with key `vctm`, see [SD-JWT VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-10.html#name-sd-jwt-vc-type-metadata)
* Dependency Updates:
    * Kotlin 2.2.0
    * AGP 8.10.0 
    * `kotlincrypto:secure-random:0.3.2` -> `kotlincrypto.random:crypto-rand:0.5.0`
        * This fixes key generation in WASM/JS
    * kotlinx.io 0.7.0
    * Update to kotlinx.datetime 0.7.1.
        * This moves Instant and Clock to stdlib
        * (but introduces typealiases for easier migration)
        * Also forces serialization 1.9.0
    * Update to latest conventions plugin:
        * Bouncy Castle 1.81!!
        * Serialization 1.9.0
        * Coroutines 1.10.2
        * Ktor 3.2.2
        * Kotest 6.0.0.M5

### 3.16.3 / 0.8.3 indispensable-only Hotfix
* Fix erroneous Base64URL encoding in JOSE data classes
    * `toString()` of `X509Certificate` and `TbsCertificate` have also been adapted to use Base64 Strict
* Add missing serializers in addition to Base64Url encoding:
    * `X509CertificateBase64Serializer`
    * `CertificateChainBase64Serializer`
* More targets:
    * watchosSimulatorArm64
    * watchosX64
    * watchosArm32
    * watchosArm64
    * androidNativeX64
    * androidNativeX86
    * androidNativeArm32
    * androidNativeArm64
* Drop OKIO dependency from `indispensable-josef` which was only ever used for to compute a SHA-256 thumbprint and replace it by a pure kotlin SHA-256 implementation


### 3.16.2 / 0.8.3 Supreme-Only Hotfix
* Set minimum iOS version to 15
* Fix Swift compat linker errors

### 3.16.2
* Lower Android `minSDK` to 21 (5.0 Lollipop) for all modules Except _Supreme_
* Update AGP to 8.6.1
* Dependency Updates:
    * KmmResult 1.9.2 (for Android SDK 21 compat)

### 3.16.1 (Supreme 0.8.1) Hotfix
* Generalized, proper COSE to MAC mapping, preventing unexpected behaviour for `HS265_24`

### 3.16.0 (Supreme 0.8.0) Symmetric Encryption and Major Cleanups
* **Note: All debug-only kotlinx.serialization for cryptographic datatypes like certificates, public keys, etc. was removed!**
    * We support robust ASN.1 encoding and mapping from/to JOSE and COSE datatypes and our ASN.1 structures support pretty printing.
    * -> There is no need for this misleading serialization support for debugging anymore.
    * `@Serializable` suggests deserialization from JSON, CBOR, etc. works, which was never universally true.
    * Getting native ASN.1 serialization for kotlinx-serialization is now a no-brainer given we support every primitive required.
    * **Serializers like `X509CertificateBase64UrlSerializer` are here to stay because those are universally useful!**
    * `ObjectIdSerializer` was renamed to `ObjectIdentifierStringSerializer`
* HMAC Support
    * **This finally cleans up the `RSAorHMAC` mess, which is a breaking change**
    * Introduce umbrella `DataIntegrityAlgorithms`, which is the parent of `SignatureAlgorithm` and `MessageAuthenticationCode`
    * `JwsAlgorithm` and `CoseAlgorithm` are now abstract, having subclasses.
    * `JwsAlgorithm`s and `CoseAlgorithm`s are now available under `.Signature` and `.MAC` respectively. There are no toplevel constants of predefined algorithms anymore!
* Symmetric Encryption
    * Supported Algorithms
        * AES
            * GCM
            * CBC-HMAC
            * CBC
            * ECB
            * KW
        * ChaCha-Poly1305
    * Add algorithm mappings to indispensable-josef **This is a binary-incompatible change**
        * `ivLength` and `encryptionKeyLength` now return `BitLength` instead of `Int`
        * `text` is now properly called `identifier`
* Move `HazardousMaterials` annotation from `supreme` to `indispensable` **This is a breaking change**
* Move `SecretExposure` annotation from `supreme` to `indispensable` **This is a breaking change**
* Expose `SecureRandom` as API dependency in `indispensable`

* Rename `CoseAlgorithm.value` -> `CoseAlgorithm.coseValue`
* Fix COSE key parsing for unordered properties
* Remove code elements deprecated in 3.15.0, related to OID4VCI and HAIP

### 3.15.2

* Parse not-implemented EC curves as `null`, e.g. in Json Web Keys

### 3.15.1 (Supreme 0.7.2)

* Fix decoding `did:key:` key identifiers containing a `#`
* Fix missing android artefact publishing for Supreme (thanks to @ephemient)
* Kotlin 2.1.20

### 3.15.0 (Supreme 0.7.1)
* **Note: We are deprecating and will soon be removing the debug-only serialization for cryptographic datatypes like certificates, public keys, etc.**
    * We support robust ASN.1 encoding and mapping from/to JOSE and COSE datatypes and our ASN.1 structures support pretty printing.
    * -> There is no need for this misleading serialization support for debugging anymore
    * `@Serializable` suggests deserialization from JSON, CBOR, etc. works, which was never universally true
    * Getting native ASN.1 serialization for kotlinx-serialization is now a no-brainer given we support every primitive required.
    * This note will be prepended to the changelog entries until the `@Serialization` annotations have been removed.
        * This will happen by Indispensable 4.0.0 / Supreme 1.0.0, if not before then.
* Introduce support for ASN.1 REAL
* Add built-in ASN.1 ENUMERATED support
* Rename `ObjectIdentifier.parse` -> `ObjectIdentifier.decodeFromAsn1ContentBytes` in accordance with other similar functions
* Update data classes for Wallet Attestation from [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html) and [OpenID4VCI](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html):
    * Deprecate `authenticationLevel` (`aal`) in `JsonWebToken`, removed from standards
    * Deprecate `key_type`, `user_authentication` in `ConfirmationClaim`, removed from standards
    * Deprecate types `WalletAttestationUserAuthentication`, `WalletAttestationKeyType`, removed from standards
    * Add `wallet_name`, `wallet_link`, `status` to `JsonWebToken`, used in Key Attestation JWT
    * Add `KeyAttestationJwt` from OpenID4VCI
* Add dedicated Android targets (SDK 30 / JDK 1.8) to all modules
* Fix internal deprecations
* Raise deprecation level to ERROR for deprecated functions:
    * `Asn1Element.Companion.parseAll`
    * `Asn1Element.Companion.parse`
    * `Asn1Element.Companion.decodeFromDerHexString`
    * `Asn1Element.asPrimitiveOctetString`
    * `CryptoPublicKey.fromJcaPublicKey`
    * `CryptoPublicKey.RSA.fromJcaPublicKey`
    * `CryptoPublicKey.EC.fromJcaPublicKey`
    * `CryptoSignature.invoke`
    * `CryptoPublicKey.RSA(n: ByteArray, e: ByteArray)`
    * `CryptoPublicKey.EC(curve: ECCurve, x: ByteArray, usePositiveY: Boolean)`
    * `CryptoPublicKey.EC(curve: ECCurve, x: ByteArray, y: ByteArray)`
    * `ECCurve.keyLengthBits`
    * `ECCurve.coordinateLengthBytes`
    * `ECCurve.signatureLengthBytes`

### 3.14.0 (Supreme 0.7.0)

* Certificate Improvements:
    * Parse X.509 certificates in V1 too
    * Change UniqueIDs from BitSet to `Asn1BitString`, enabling correct encoding of borked bit strings
* Change variance of generic on `Asn1Encodable` and `Asn1Decodable`
* **Key Agreement Support**
    * ECDH

### 3.13.0 (Supreme 0.6.4)

* Fix COSE key serialization
* Refactor `Asn1Integer` to use `UByteArray` internally instead of a list
* Fix ASN.1 decoding flaw for a very specific length encoding
* Performance optimization: Instantiate fewer `KmmResult`s
* Move `PemEncodable`/`PemDecodable` from _indispensable_ to _indispensable-asn1_ module.
* More comprehensive PEM encoding/decoding support:
    * `CryptoPublicKey`
        * Note that PKCS1 encoding of RSA keys is not supported as it is discouraged (decoding is supported)
        * ANSI encoding and decoding is also unsupported, because decoding requires context and encoding this way is incomplete
    * `X509Certificate`
    * CSR (`Pkcs10CertificationRequest`)
* Change `CoseHeader.certificateChain` (CBOR element 33 `x5chain`) from a single byte array to a list of byte arrays, acc. to specification
* Remove `CoseHeader.coseKey`, which has been an unofficial addition from OID4VCI, but has been removed since

### 3.12.1 (Supreme 0.6.3)

* Add COSE object creation with detached payload, i.e. setting a `null` payload in `CoseSigned`, and clients are responsible to transport the payload separately

### 3.12.0 (Supreme 0.6.2)

* Fix COSE signature verification (this is breaking change in `indispensable-cosef`):
    * Introduce class `CoseSignedBytes` which holds the bytes as transmitted on the wire
    * Add property `wireFormat` to `CoseSigned` to hold those bytes
    * Create new `CoseSigned` objects by calling `CoseSigned.create()` instead of using a constructor
    * Prepare COSE signature input by calling `CoseSigned.prepare()`
    * In `CoseSigned`, member `protectedHeader` is now a `CoseHeader`, not a `ByteStringWrapper<CoseHeader>`
    * In `CoseSigned`, member `rawSignature` (`ByteArray`) is now `signature` (`CryptoSignature.RawByteEncodable`)

### 3.11.1 (Supreme 0.6.1)

* Fix `CoseSigned` JSON serialization

### 3.11.0 (Supreme 0.6.0)

* Kotlin 2.1.0
* Bouncy Castle 1.79!! for JVM targets
* Implement members in `JsonWebToken` and `ConfirmationClaim` for OpenID4VC High Assurance Interoperability Profile with SD-JWT VC
* Add utility methods to `Asn1Integer`
    * Additional constructor methods: `fromByteArray`, `fromUnsignedByteArray`
    * Additional instance methods: `isZero`, `magnitude`, `bitLength`
    * Additional conversion methods for Java BigInteger and iospin BigInteger
* Refactor `CryptoPublicKey.Rsa` to use `Asn1Integer`
    * Fixes JWS/COSE encoding for non-standard exponents (with MSBit 1)
* Add type parameter to `CoseSigned` for its payload (tagging with tag 24 when necessary)
    * Changes primary constructor visibility to `internal` to check for `ByteStringWrapper` as payload type, which shall be rejected
    * Fix serialization with Json
* Do not use DID key identifiers as keyId for `CoseKey`
* Fix BitSet iterator
* Add cose header `typ`
* Allow `assertTag` override also for `Asn1Integer` (was missing before)
* Sanitized `Asn1OctetString` inheritors' equality behavior
    * Two `Asn1OctetString`s are always equal if their contents are equal
* Make `Asn1Integer` an `Asn1Encodable<String>`
* **PEM Encoding**
    * Introduce `PemEncodable` interface, derived from `Asn1Encodable`
    * Introduce `PemDecodable` interface, derived from `Asn1Decodable`
* Add **Private Key**
    * Add **Private Key Representation** to `indispensable`
    * Parsing of PEM and DER-encoded private keys in  `indispensable`
    * Introduce `SignatureAlgorithm.signerFor(privateKey)` in `supreme` to create signers backed by (previously parsed, or manually constructed) private keys
    * Export of private keys from ephemeral signers (and only ephemeral signers) in combination with a new `@SecretExposure` annotation in `supreme`
* Add helpers for smoother iOS interop:
    * `ECCurve.iosEncodedPublicKeyLength`
    * `ECCurve.iosEncodedPrivateKeyLength`
    * `ECCurve.Companion.fromIosEncodedPublicKeyLength`
    * `ECCurve.Companion.fromIosEncodedPrivateKeyLength`
* Renames (old names are kept with a deprecation warning):
    * `getJcaPublicKey()` -> `toJcaPublicKey()`
* Support RSA8192

### 3.10.0 (Supreme 0.5.0) More ~~cowbell~~ targets!
A new artifact, minor breaking changes and a lot more targets ahead!

The public API remains _almost_ unchanged. Breaking API changes are:

* Some parsing methods migrating from a `ByteIterator` to kotlinx-io `Source`
* Move `ensureSize` from package `asn1` to `misc`
* Change CSR to take an actual `CryptoSignature` instead of a ByteArray
* Remove Legacy iOS Attestation
* Add type parameter to `JwsSigned` for its payload
* Add type parameter to `JweDecrypted` for its payload
* `JwsSigned.prepareSignatureInput` now returns a raw ByteArray
* Move `BitSet` from `io` to `asn1` package

The internals have changed substantially, however, and some fixes lead to behavioural changes.
Therefore, be sure to match Signum versions if multiple libraries pull it in as transitive dependency.
Better safe than sorry!  
The full list of changes is:

* Discrete ASN.1 module `indispensable-asn1` supporting the following platforms:
    * JVM
    * Android
    * iOS
    * watchOS
    * tvOS
    * JS
    * wasm/JS
    * Linux X64
    * Linux AARCH64
    * MinGw X64
* More targets for `indispensable`,  `indispensable-josef`, `indispensable-cosef`
    * JVM
    * Android
    * iOS
    * watchOS
    * tvOS
    * JS
    * wasm/JS
    * Linux X64
    * Linux AARCH64
    * MinGw X64
* KmmResult 1.9.0
* Multibase 1.2.1
* Introduce generic tag assertion to `Asn1Element`
* Change CSR to take an actual `CryptoSignature` instead of a ByteArray
* Introduce shorthand to create CSR from TbsCSR
* Introduce shorthand to create certificate from TbsCertificate
* Remove requirement from CSR to have certificate extensions
* Fix CoseSigned equals
* Base OIDs on unsigned varint instead of UInt
* Directly support UUID-based OID creation
* Implement hash-to-curve and hash-to-scalar as per RFC9380
* Rename `decodeFromDerHexString` to `parseFromDerHexString`
* Move `ensureSize` from package `asn1` to `misc`
* Move `BitSet` from `io` to `asn1` package
* Use kotlinx-io as primary source for parsing
    * Base number encoding/decoding on kotlinx-io
        * Remove parsing from iterator
    * Base ASN.1 encoding and decoding on kotlinx-io
        * Remove single element decoding from Iterator
* Introduce `prepareDigestInput()` to `IosHomebrewAttestation`
* Remove Legacy iOS Attestation
* Add type parameter to `JwsSigned` for its payload
* Add type parameter to `JweDecrypted` for its payload
* `JwsSigned.prepareSignatureInput` now returns a raw ByteArray
* Tests that do not depend on BouncyCastle/JCA are now performed for all targets
* Remove Napier dependency

### 3.9.0 (Supreme 0.4.0)

* Move `Attestation` from Supreme to Indispensable
* Rename `parse()` to `deserialize()` in `JwsSigned` and `JweEncrypted` to align with COSE
* Rename `CryptoPublicKey.Rsa` -> `CryptoPublicKey.RSA` for consistency reasons
* Add HMAC JCA names, properties used in JSON Web Encryption

### 3.8.2 (Supreme 0.3.2)
* Less destructive Hotfix for [KT-71650](https://youtrack.jetbrains.com/issue/KT-71650/Invalid-Objective-C-Header-in-XCFramework)
* Re-enables export of `Asn1Element.Tag` class to ObjC.

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
    * `datatypes-cose` pulls in latest 1.8.0 serialization SNAPSHOT from upstream
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

 
## 2.0

### 2.6.0
* Pull in `JsonWebKeySet` from `vclib`
* Implement JWK Set Url (`jku`) in JWS headers
* Implement Attestation JWT (`jwt`) in JWS headers
* Implement Confirmation keys (`cnf`) in JWT
* Implement `CborWebToken` (RFC 8392)
* Boolean ASN.1 decoding helper function
* Certificate to/from JCA certificate conversion functions

### 2.5.0
* Parse more certificates from `x5c` in JWS headers
* Kotlin 1.9.23 thanks to updated conventions
* Generate `KnownOIDs` using [KotlinPoet](https://square.github.io/kotlinpoet/)
* Work around KT-65315 thanks to updated conventions
* BigNum as API dependency and iOS export (seems nonsensical,
  but is somehow required when using this inside a compose multiplatform app)
* Rename `BERTags.NULL` to `BERTags.ASN1_NULL` to fix broken ObjC export

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

### 2.3.0
* Change `CryptoPublicKey.toJsonWebKey()` return type from `KmmResult<JsonWebKey>` to `JsonWebKey`
* Add `CryptoSignature.parseFromJca` function
* Refactor `CryptoPublicKey.keyID` to `CryptoPublicKey.didEncoded` to better reflect what it actually is
* Rename `CryptoPublicKey.fromKeyId` to `CryptoPublicKey.fromDid`

### 2.2.1
* Update conventions
    * Rename CBOR annotations
    * Target Java 17

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


### 2.0.0
* JWS Support
* Bugfixes and streamlining all over the place
* Proper BIT STRING
* BitSet (100% Kotlin BitSet implementation)
* Recursively parsing (and encapsulating) ASN.1 structures in OCTET Strings
* Initial pretty-printing of ASN.1 Strucutres
* Massive ASN.1 builder DSL streamlining
* More convenient explicit tagging

## 1.0

### 1.0.0
First public release
