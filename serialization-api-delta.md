# Kotlinx Serialization DER API Delta (vs `development`)

This page documents API and behavior changes introduced on this branch relative to `development`.

Scope:
- Production code in `indispensable-asn1` and `indispensable`
- Public/consumer-visible behavior and entry points
- Excludes test-only helper classes

## 1. New DER/Kotlinx Serialization Surface

### 1.1 New package
`at.asitplus.signum.indispensable.asn1.serialization`

### 1.2 New format entry points
Defined in `indispensable-asn1/src/commonMain/.../serialization/Der.kt` and `.../serialization/api/DER.kt`.

```kotlin
val DER
fun DER(config: () -> Unit = {}): Der

inline fun <reified T> Der.encodeToDer(value: T): ByteArray
inline fun <reified T> Der.encodeToTlv(value: T): Asn1Element
inline fun <reified T> Der.decodeFromDer(source: ByteArray): T
inline fun <reified T> Der.decodeFromTlv(source: Asn1Element): T

fun <T> Der.encodeToDer(serializer: SerializationStrategy<T>, value: T): ByteArray
fun <T> Der.encodeToTlv(serializer: SerializationStrategy<T>, value: T): Asn1Element
fun <T> Der.decodeFromDer(source: ByteArray, deserializer: DeserializationStrategy<T>): T
fun <T> Der.decodeFromTlv(source: Asn1Element, deserializer: DeserializationStrategy<T>): T
```

Note:
- `DER(config)` currently accepts a config lambda but does not apply any settings yet.

### 1.3 New ASN.1 annotation model
Defined in `indispensable-asn1/src/commonMain/.../serialization/Annotations.kt`.

```kotlin
@Asn1nnotation(
  vararg layers: Layer,
  asBitString: Boolean = false,
  encodeNull: Boolean = false,
  asChoice: Boolean = false
)
```

Layer model:
- `Layer(Type.OCTET_STRING)`
- `Layer(Type.EXPLICIT_TAG, <singleTag>)`
- `Layer(Type.IMPLICIT_TAG, <singleTag>)`

`Type` enum:
- `OCTET_STRING`
- `EXPLICIT_TAG`
- `IMPLICIT_TAG`

Behavior:
- Class-level and property-level layers are both supported.
- Layer order is significant and applied in declared order.
- `asBitString` changes `ByteArray` encoding from OCTET STRING to BIT STRING.
- `encodeNull` forces explicit ASN.1 NULL encoding for null values instead of omission.
- `asChoice` enables CHOICE-mode sealed polymorphism (see below).

### 1.4 New serializer SPI
Defined in `indispensable-asn1/src/commonMain/.../serialization/SerializerImplementations.kt`.

```kotlin
interface Asn1Serializer<A : Asn1Element, T : Asn1Encodable<A>>
  : Asn1Decodable<A, T>, KSerializer<T>
```

Default contract:
- Uses ASN.1 DER only (`DerEncoder`/`DerDecoder`).
- Throws `SerializationException` for non-ASN.1 formats unless a type overrides `serialize/deserialize` for fallback behavior.

Also added:
- `Asn1ElementSerializer` (DER-only serializer for raw `Asn1Element` values).

## 2. Polymorphism, CHOICE, and Ambiguity Rules

### 2.1 Runtime ambiguity detection for optional/nullable layouts
Implemented in `AmbiguityChecks.kt`, enforced from encoder/decoder.

What now fails:
- Class/object layouts where an omittable field can share leading tag(s) with a following field and skipped fields in between are also omittable.

Typical ambiguous examples:
- Multiple nullable strings without disambiguating tags
- Nullable numeric sequences like `Long?`, `Int?`, `Short?`, `Byte?`
- Nullable `Map` followed by `List` without extra tagging

How to disambiguate:
- Add `@Asn1nnotation(Layer(Type.IMPLICIT_TAG, ...))` or explicit tagging layers
- Or force explicit null representation with `encodeNull = true`
- Or use field types with disjoint ASN.1 leading tags

### 2.2 CHOICE modeling
Implemented via `@Asn1nnotation(asChoice = true)`.

Rules:
- CHOICE mode is sealed-polymorphism only.
- Encode: selected arm must encode to exactly one ASN.1 element.
- Decode: all sealed alternatives are tried against the same input element.
  - 0 matches -> failure (`SerializationException`, no matching alternative)
  - >1 matches -> failure (`SerializationException`, ambiguous CHOICE)
  - 1 match -> success

### 2.3 Non-CHOICE polymorphism
- Regular kotlinx polymorphic structure encoding/decoding remains available.
- CHOICE mode is opt-in and does not replace default polymorphic representation.

### 2.4 Extra strictness
- Decoder rejects superfluous ASN.1 children for class/object structures.


## 3. Collection and Primitive Behavior in DER Format

Behavior covered by branch tests and serializer implementation:
- `List<T>` -> ASN.1 SEQUENCE
- `Map<K,V>` -> supported (sequence-based structure)
- `Set<T>` -> ASN.1 SET semantics
- `ByteArray` -> OCTET STRING by default; BIT STRING with `asBitString = true`
- Nullable values:
  - Omitted by default
  - Encoded as ASN.1 NULL with `encodeNull = true`

## 4. Types Newly Wired for Kotlinx Serialization

## 4.1 `indispensable-asn1` core types

### DER-only serializers
- `Asn1Element` (and hierarchy via `Asn1ElementSerializer`):
  - `Asn1Structure`
  - `Asn1ExplicitlyTagged`
  - `Asn1CustomStructure`
  - `Asn1EncapsulatingOctetString`
  - `Asn1PrimitiveOctetString`
  - `Asn1Set`
  - `Asn1SetOf`
  - `Asn1Primitive`
  - `Asn1OctetString`
- `Asn1BitString` (Companion implements `Asn1Serializer`)
- `Asn1Time` (Companion implements `Asn1Serializer`)

### DER + non-ASN.1 fallback serializers
- `Asn1Integer`
  - DER: ASN.1 INTEGER
  - Non-ASN.1: decimal string (`Asn1IntegerStringSerializer`)
- `Asn1Real`
  - DER: ASN.1 REAL
  - Non-ASN.1: human-readable string (`Asn1RealStringSerializer`)
- `Asn1String` (all variants)
  - DER: preserves ASN.1 string subtype/tag
  - Non-ASN.1: plain string (decoded back as UTF8 variant)
- `ObjectIdentifier`
  - DER: ASN.1 OID
  - Non-ASN.1: dotted string form (`ObjectIdentifierStringSerializer`)

### Signature change
- `Asn1Primitive.asAsn1BitString(assertTag: Asn1Element.Tag = Asn1Element.Tag.BIT_STRING)`
  - Added optional `assertTag` parameter to support tag overrides.

## 4.2 `indispensable` types

These types were annotated with `@Serializable` and wired with ASN.1 serializers:

- `CryptoPrivateKey` hierarchy:
  - `CryptoPrivateKey`
  - `CryptoPrivateKey.WithPublicKey`
  - `CryptoPrivateKey.RSA`
  - `CryptoPrivateKey.RSA.PrimeInfo`
  - `CryptoPrivateKey.EC`
  - `CryptoPrivateKey.EC.WithPublicKey`
  - `CryptoPrivateKey.EC.WithoutPublicKey`
  - `EncryptedPrivateKey`
- `CryptoPublicKey` hierarchy:
  - `CryptoPublicKey`
  - `CryptoPublicKey.RSA`
  - `CryptoPublicKey.EC`
- `CryptoSignature` hierarchy:
  - `CryptoSignature`
  - `CryptoSignature.EC`
  - `CryptoSignature.EC.DefiniteLength`
  - `CryptoSignature.RSA`
- Key agreement and MAC:
  - `KeyAgreementPublicValue`
  - `KeyAgreementPublicValue.ECDH`
  - `HMAC`
- PKI types:
  - `TbsCertificationRequest`
  - `Pkcs10CertificationRequest`
  - `Pkcs10CertificationRequestAttribute`
  - `RelativeDistinguishedName`
  - `AttributeTypeAndValue` + subclasses
  - `TbsCertificate`
  - `X509Certificate`
  - `X509CertificateExtension`

Special case:
- `X509SignatureAlgorithm` now has `X509SignatureAlgorithmSerializer` (string OID representation; not DER-only).

### 4.3 Additional convenience overloads
Defined in `indispensable/src/commonMain/.../asn1/serialization/SerializationAddons.kt`:

```kotlin
fun Der.encodeToDer(value: CryptoPrivateKey.WithPublicKey<*>): ByteArray
fun Der.encodeToTlv(value: CryptoPrivateKey.WithPublicKey<*>): Asn1Element
fun <T : CryptoPrivateKey.WithPublicKey<*>> Der.decodeFromTlv(source: Asn1Element): CryptoPrivateKey.WithPublicKey<*>
fun <T : CryptoPrivateKey.WithPublicKey<*>> Der.decodeFromDer(source: ByteArray): CryptoPrivateKey.WithPublicKey<*>
```

Purpose:
- Avoid star-projection friction when working with `CryptoPrivateKey.WithPublicKey<*>`.

## 5. Non-ASN.1 Format Compatibility Rules

By design in this branch:
- Complex ASN.1/domain serializers (using `Asn1Serializer` defaults) reject non-ASN.1 formats.
- Scalar bridge types may support non-ASN.1 formats through explicit fallback implementations:
  - `Asn1Integer`, `Asn1Real`, `Asn1String`, `ObjectIdentifier`
  - `X509SignatureAlgorithm` (string serializer)

Practical implication:
- `Json.encodeToString(...)` works for supported scalar bridge types.
- For complex ASN.1 structures, use `DER.encodeToDer(...)` / `DER.decodeFromDer(...)`.

## 6. Build and Tooling Delta
- `indispensable-asn1/build.gradle.kts`
  - Added compiler arg: `-Xemit-jvm-type-annotations`.

## 7. Migration Notes from `development`

If existing models start failing after switching to this branch:
1. Check nullable/optional field ordering; ambiguity is now rejected at runtime.
2. Add `@Asn1nnotation` tags (`IMPLICIT_TAG`/`EXPLICIT_TAG`) where needed.
3. Use `encodeNull = true` for nullable fields that must stay positionally visible.
4. For CHOICE semantics, use sealed hierarchies with `@Asn1nnotation(asChoice = true)`.
5. For non-ASN.1 formats, use only bridge serializers that explicitly support fallback.
