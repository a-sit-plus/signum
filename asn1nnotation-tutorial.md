# ASN.1 DER + Kotlinx Serialization Tutorial (`@Asn1nnotation`)

This tutorial explains the DER format integration in this branch from first principles to advanced ambiguity handling.

Goal:
- show how serialization works without annotations
- explain what `@Asn1nnotation` controls
- prove why ambiguity checks are necessary (with counterexamples)
- show how to model polymorphism and `CHOICE`
- show how to handle custom serializers safely with `Asn1Shape`

---

## 1. Why this is strict

ASN.1 DER is schema-driven and position-sensitive.

For a `SEQUENCE`, decoding usually walks left to right:
1. read next child element
2. decide which field it belongs to
3. continue from there

That only works if each field boundary is deterministically recoverable.

If a field is optional/nullable and omitted, the decoder must decide whether the next child belongs to:
- the omitted field (present), or
- the next field (omitted previous)

If both are possible, you get ambiguity.

This branch intentionally **fails hard** in those situations instead of guessing.

Why hard-fail:
- guesswork causes silent mis-decoding
- silent mis-decoding is dangerous in PKI/crypto code
- deterministic failure is easier to fix with explicit tags or shape contracts

---

## 2. Baseline behavior (no `@Asn1nnotation`)

Without annotation, the codec uses descriptor-driven defaults.

Common mapping:
- `Boolean` -> ASN.1 `BOOLEAN`
- `Byte`/`Short`/`Int`/`Long` -> ASN.1 `INTEGER`
- `Float`/`Double` -> ASN.1 `REAL`
- `String`/`Char` -> ASN.1 string primitives
- `ByteArray` -> ASN.1 `OCTET STRING`
- data class/object -> ASN.1 `SEQUENCE`
- `List<T>` -> ASN.1 `SEQUENCE`
- `Map<K,V>` -> ASN.1 `SEQUENCE`
- `Set<T>` -> ASN.1 `SET`

Nullable default:
- `null` is omitted (no child emitted)

### Minimal example

```kotlin
@Serializable
data class Person(
    val name: String,
    val age: Int,
)
```

Equivalent ASN.1 shape:

```asn1
Person ::= SEQUENCE {
  name UTF8String,
  age  INTEGER
}
```

No ambiguity here.

---

## 3. `@Asn1nnotation` at a glance

```kotlin
@Asn1nnotation(
    vararg layers: Layer,
    asBitString: Boolean = false,
    encodeNull: Boolean = false,
    asChoice: Boolean = false,
    shape: Asn1Shape = Asn1Shape(),
)
```

You can place it on:
- class/object
- property
- inline wrapper type

`layers` are applied in declared order, outermost first.

Layer kinds:
- `Layer(Type.IMPLICIT_TAG, tag)`
- `Layer(Type.EXPLICIT_TAG, tag)`
- `Layer(Type.OCTET_STRING)`

---

## 4. Tagging and wrapping, step by step

## 4.1 IMPLICIT

IMPLICIT changes the visible tag of the current value, without adding an extra nesting node.

```kotlin
@Serializable
data class Payload(
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 0uL))
    val value: String,
)
```

ASN.1 intent:

```asn1
Payload ::= SEQUENCE {
  value [0] IMPLICIT UTF8String
}
```

Use IMPLICIT when schema says the inner type is replaced by a context tag.

## 4.2 EXPLICIT

EXPLICIT adds an extra wrapper element with its own tag.

```kotlin
@Serializable
data class Payload(
    @Asn1nnotation(Layer(Type.EXPLICIT_TAG, 0uL))
    val value: String,
)
```

ASN.1 intent:

```asn1
Payload ::= SEQUENCE {
  value [0] EXPLICIT UTF8String
}
```

Use EXPLICIT when schema requires a tagged wrapper around the original TLV.

## 4.3 OCTET STRING wrapper

`Layer(Type.OCTET_STRING)` encapsulates a value as an ASN.1 OCTET STRING payload.

```kotlin
@Serializable
@Asn1nnotation(Layer(Type.OCTET_STRING))
data class Wrapped(val value: Int)
```

Use this for schemas that carry encoded sub-structures inside OCTET STRING containers.

## 4.4 Layer order matters

This is not cosmetic. Different order => different DER tree.

```kotlin
@Asn1nnotation(
    Layer(Type.EXPLICIT_TAG, 3uL),
    Layer(Type.OCTET_STRING),
    Layer(Type.IMPLICIT_TAG, 1uL),
)
```

means:
1. outer explicit [3]
2. inside it octet wrapper
3. inside that an implicitly tagged payload

Change order and you change semantics.

If you stack multiple IMPLICIT layers at the same level, the outermost visible tag is the one that wins in the final TLV view. In practice, that means order is part of your schema contract, not just syntax.

---

## 5. Class-level vs property-level annotations

Both participate.

Typical use:
- class-level for type-wide schema rules
- property-level for field-specific schema rules

Both are relevant for ambiguity checks too. If a class has a leading class-level tag, that tag contributes to disambiguation when the class appears as a field.

Counterexample:
- two nullable class fields with no distinguishing leading tag -> ambiguous
- adding different class-level tags to those classes -> unambiguous

---

## 6. Nullable handling and why ambiguity appears

Default nullable behavior: omission.

Example:

```kotlin
@Serializable
data class Example(
    val first: String,
    val middle: String?,
    val last: String,
)
```

This is ambiguous when `middle` is omitted:
- next element is `String`
- but both `middle` and `last` are also `String`
- same leading ASN.1 kind, same tag family

Decoder cannot prove which field it belongs to.

So this branch throws `SerializationException`.

### How to fix

1. Add disambiguating tag(s):

```kotlin
@Serializable
data class Example(
    val first: String,
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 0uL))
    val middle: String?,
    val last: String,
)
```

2. Or use `encodeNull = true` so `null` is emitted instead of omitted (when safe).

---

## 6.1 How the ambiguity checker actually decides

At class/object boundaries, the codec computes each field's possible leading tags and then validates optional/nullable layout.

Conceptually:
1. mark fields as omittable (`nullable` without `encodeNull=true`, or Kotlin optional/default)
2. infer each field's possible leading ASN.1 tag set
3. for each omittable field, compare against following fields reachable by omitting intermediate omittable fields
4. if leading-tag overlap exists, reject as ambiguous

Important nuance:
- this runs on both encode and decode paths, so ambiguity fails early in both directions
- class-level and property-level ASN.1 layers both contribute to the inferred leading tags

There are three leading-tag knowledge states:
- `Exact`: finite set of concrete leading tags known
- `ValueDependent`: serializer says tag depends on runtime value
- `UnknownInfer`: inference cannot derive a safe leading-tag set

For nullable omission in non-trailing positions:
- `Exact` can be checked for overlap
- `ValueDependent` and `UnknownInfer` are rejected as undecidable unless you add disambiguation

Why trailing nullable is treated differently:
- if a nullable/optional field is last, there is no later field to shift into, so omission does not create positional ambiguity for subsequent fields

---

## 7. `encodeNull = true`: useful but subtle

`encodeNull = true` changes nullable behavior from omission to explicit null encoding.

This can remove omission ambiguity in many cases.

Example:

```kotlin
@Serializable
data class Example(
    @Asn1nnotation(encodeNull = true)
    val maybeInt: Int?,
    val next: Int,
)
```

Without `encodeNull`, first field could disappear and collide with `next`.
With `encodeNull`, `null` has its own concrete encoding and field position remains explicit.

### But: dangerous combo exists

`encodeNull = true` + IMPLICIT + primitive that can encode empty content can become ambiguous.

Classic bad case:

```kotlin
@Serializable
data class Bad(
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 10uL), encodeNull = true)
    val value: String?
)
```

Why bad:
- encoded null under IMPLICIT can look like tag `[10]` length 0
- empty string under IMPLICIT can also be tag `[10]` length 0
- indistinguishable

The codec rejects this.

Types commonly affected by empty-content ambiguity:
- `String`
- `Float` / `Double` (`REAL`)
- `ByteArray` when represented as OCTET STRING content

Safe examples under IMPLICIT + encodeNull:
- `Int?`, `Long?`, `Short?` (INTEGER has no valid zero-length non-null encoding)
- `ByteArray` with `asBitString = true` (BIT STRING encoding keeps an initial unused-bits byte)

---

## 8. Primitive-family collisions that are unambiguous in Kotlin but ambiguous in ASN.1

Kotlin types can be distinct while ASN.1 tags are identical.

Examples:
- `Long`, `Int`, `Short`, `Byte` -> all `INTEGER`
- `Float`, `Double` -> both `REAL`

So this layout is ambiguous when nullable/omittable:

```kotlin
@Serializable
data class Bad(
    val a: Long?,
    val b: Int?,
    val c: Short?,
    val d: Byte?,
    val e: Float?,
    val f: Double?,
)
```

Fixes:
- tag each field uniquely (implicit or explicit)
- or partially tag enough fields such that reachable optional paths no longer collide

The branch has both positive and negative tests for:
- fully tagged
- fully untagged
- partially tagged ambiguous
- partially tagged unambiguous

---

## 9. Collection collisions: `Map` vs `List`

Both map and list have leading `SEQUENCE` in this codec.

So this is ambiguous:

```kotlin
@Serializable
data class Bad(
    val maybeMap: Map<Int, Boolean>?,
    val values: List<Int>,
)
```

If `maybeMap` is omitted, next child is still `SEQUENCE`, indistinguishable from map presence.

Fix with tag:

```kotlin
@Serializable
data class Good(
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 40uL))
    val maybeMap: Map<Int, Boolean>?,
    val values: List<Int>,
)
```

---

## 10. `asBitString`

`asBitString = true` affects `ByteArray` encoding:
- default `ByteArray` -> OCTET STRING
- with `asBitString` -> BIT STRING

Useful for key material/signature bit fields where schema says BIT STRING.

Example:

```kotlin
@JvmInline
@Serializable
@Asn1nnotation(asBitString = true)
value class SubjectPublicKeyBits(val bytes: ByteArray)
```

When nested with layers, outer annotation context controls final wrapping.

---

## 11. Polymorphism and ASN.1 `CHOICE`

## 11.1 Default polymorphism (no `asChoice`)

Regular kotlinx polymorphism uses its normal representation (type + value structure).
That is not ASN.1 `CHOICE`.

## 11.2 CHOICE mode

Use sealed hierarchy + `@Asn1nnotation(asChoice = true)`:

```kotlin
@Serializable
@Asn1nnotation(asChoice = true)
sealed interface Name

@Serializable
data class Rfc822Name(val value: String) : Name

@Serializable
@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 2uL))
data class DnsName(val value: String) : Name
```

Encoding:
- selected arm is encoded directly as a single TLV
- no discriminator wrapper

Decoding:
- try each sealed arm against same element
- 0 matches -> fail
- 1 match -> success
- >1 matches -> fail as ambiguous choice

That is exactly the behavior needed for schema-driven CHOICE.

### Why sealed only

Open polymorphism cannot guarantee a closed, schema-known set of alternatives at decode time.
CHOICE requires a fixed alternative set.

---

## 12. Advanced custom serializers and `Asn1Shape`

Most models can be inferred from descriptors and tags.

Custom serializers can break inference, especially when leading tag depends on runtime value.

`shape` lets you state the leading-tag contract explicitly.

Why this exists:
- descriptors are often enough for generated serializers
- custom serializers can emit TLV that descriptor metadata does not reveal
- ambiguity checks must reason about leading tags without executing arbitrary user serializer code
- `shape` is the contract bridge between custom runtime behavior and static ambiguity analysis

## 12.1 `INFER` (default)

```kotlin
@Asn1nnotation(shape = Asn1Shape())
```

Use descriptor-based inference.

Good when:
- generated serializers
- custom serializers that still map to a descriptor with stable and inferable leading tag

## 12.2 Exact leading tags

```kotlin
@Asn1nnotation(
    shape = Asn1Shape(
        leadingTags = [
            Asn1LeadingTag(
                kind = Asn1LeadingTagKind.TAG,
                tagClass = TagClass.UNIVERSAL,
                tag = 2uL,
                constructed = Asn1ConstructedBit.PRIMITIVE,
            ),
            Asn1LeadingTag(
                kind = Asn1LeadingTagKind.TAG,
                tagClass = TagClass.UNIVERSAL,
                tag = 16uL,
                constructed = Asn1ConstructedBit.CONSTRUCTED,
            ),
        ]
    )
)
```

Use this when a serializer can emit one of a finite known set of tags.

Typical case:
- custom serializer emits either INTEGER or SEQUENCE, and both are intentional and bounded

## 12.3 Value-dependent leading tag

```kotlin
@Asn1nnotation(
    shape = Asn1Shape(
        leadingTags = [Asn1LeadingTag(kind = Asn1LeadingTagKind.VALUE_DEPENDENT)]
    )
)
```

Use this when runtime value decides the leading tag and no finite static set is safe.

Important:
- `VALUE_DEPENDENT` must be the only entry
- if such a field is nullable/omittable and not trailing, layout becomes undecidable unless you add disambiguation (for example explicit tag layer)

Typical fix:
- keep value-dependent serializer as-is
- add an outer property tag (`IMPLICIT` or `EXPLICIT`) so field selection is no longer value-dependent

## 12.4 `baseForm` and `emptyNonNull`

These refine null-sentinel safety for custom serializers under IMPLICIT+encodeNull.

- `baseForm`: primitive vs constructed outer form
- `emptyNonNull`: whether non-null values may legally encode with zero content length

They exist so custom serializers can declare behavior that descriptors cannot infer.

This matters specifically for IMPLICIT+encodeNull null-sentinel safety:
- if base is primitive and can encode empty non-null content, null may collide with non-null empty
- if base is primitive and cannot encode empty non-null content, zero-length can still be a safe null sentinel
- if base is constructed, constructed-bit distinction can help disambiguate null sentinel

Example declaration when you know your custom primitive is never empty:

```kotlin
@Asn1nnotation(
    Layer(Type.IMPLICIT_TAG, 7uL),
    encodeNull = true,
    shape = Asn1Shape(
        baseForm = Asn1BaseForm.PRIMITIVE,
        emptyNonNull = Asn1EmptyNonNull.NEVER,
    )
)
```

Without this, inference may conservatively reject ambiguous-looking null handling.

---

## 13. Real ASN.1 schema examples that justify this strictness

## 13.1 Optional fields in `SEQUENCE`

Bad schema shape:

```asn1
Bad ::= SEQUENCE {
  a UTF8String,
  b UTF8String OPTIONAL,
  c UTF8String
}
```

If `b` omitted, decoder cannot distinguish `c` from `b`.

Good shape:

```asn1
Good ::= SEQUENCE {
  a UTF8String,
  b [0] IMPLICIT UTF8String OPTIONAL,
  c UTF8String
}
```

## 13.2 X.509-style optional tail fields

RFC 5280 `TBSCertificate` uses context tags on optional fields near the tail:
- `issuerUniqueID  [1] IMPLICIT UniqueIdentifier OPTIONAL`
- `subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL`
- `extensions      [3] EXPLICIT Extensions OPTIONAL`

This is exactly the kind of schema discipline needed for deterministic decoding.

## 13.3 CHOICE with colliding alternatives

Bad CHOICE:

```asn1
BadChoice ::= CHOICE {
  a UTF8String,
  b UTF8String
}
```

Both arms share the same leading tag. Decode is ambiguous.

Good CHOICE:

```asn1
GoodChoice ::= CHOICE {
  a [0] IMPLICIT UTF8String,
  b [1] IMPLICIT UTF8String
}
```

---

## 14. “Why not just ignore edge cases?”

Short answer: because they are not edge cases in DER schema work.

If ignored, you get one of two bad outcomes:
1. silent wrong decode (field shift, wrong CHOICE arm, wrong null interpretation)
2. non-portable encoding that other strict DER implementations reject

In cryptographic and certificate code, silent wrong decode is worse than a hard failure.

This branch chooses deterministic behavior:
- ambiguous layouts are rejected early
- custom serializers must provide shape hints when inference is insufficient
- CHOICE ambiguity fails instead of guessing

---

## 15. Practical authoring checklist

When modeling ASN.1 with Kotlin data classes:

1. Start with plain `@Serializable` and no annotation.
2. Add `@Asn1nnotation` only where schema requires tagging/wrapping/choice/null policy.
3. For nullable/optional fields in the middle of a sequence, ensure leading-tag disjointness.
4. If using `encodeNull = true`, verify no IMPLICIT+empty-content collision.
5. For sealed CHOICE, ensure alternatives are tag-distinguishable.
6. For custom serializers with dynamic leading tags, declare `shape`.
7. Prefer explicit disambiguation over relying on decoder heuristics.

---

## 16. Where to look in this repo

Core implementation:
- `indispensable-asn1/src/commonMain/kotlin/at/asitplus/signum/indispensable/asn1/serialization/Annotations.kt`
- `indispensable-asn1/src/commonMain/kotlin/at/asitplus/signum/indispensable/asn1/serialization/AmbiguityChecks.kt`
- `indispensable-asn1/src/commonMain/kotlin/at/asitplus/signum/indispensable/asn1/serialization/DerEncoder.kt`
- `indispensable-asn1/src/commonMain/kotlin/at/asitplus/signum/indispensable/asn1/serialization/DerDecoder.kt`

Behavioral examples/tests:
- `indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/SerializationImplicitTaggingTest.kt`
- `indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/SerializationAmbiguityDetectionTest.kt`
- `indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/SerializationPrimitiveNullAmbiguityTest.kt`
- `indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/SerializationPolymorphismAndChoiceTest.kt`
- `indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/SerializationShapeContractTest.kt`
- `indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/SerializationMapSupportTest.kt`
- `indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/SerializationNullAndSetTest.kt`

---

## 17. TL;DR design contract

- DER decoding must be deterministic.
- `@Asn1nnotation` is the single ASN.1 control surface.
- Ambiguity is rejected, not guessed.
- CHOICE is sealed and tag-driven.
- Custom serializers can opt into strict contracts via `Asn1Shape`.

If you keep those five rules in mind, the rest of the system behavior is predictable.
