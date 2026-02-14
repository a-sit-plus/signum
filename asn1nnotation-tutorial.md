# ASN.1 DER + Kotlinx Serialization Tutorial (Current Model)

This tutorial reflects the current implementation in this branch.

It explains:
- how DER encoding works with no ASN.1 annotations
- what each ASN.1 annotation does now
- why and when ambiguity is rejected
- how serializer `leadingTags` participate in ambiguity checks
- how strict OID-open-polymorphism registration works (`IdentifiedBy` + `registerSubtype`)
- how to model EXPLICIT tagging, OCTET wrapping, polymorphism, and CHOICE

## 1. Big Picture

The codec is strict by design.

For class-like structures (`SEQUENCE`/`SET`), decoding walks children left-to-right. If a nullable/optional field can be omitted and the next field could start with the same leading tag, decoding becomes undecidable. The codec rejects those layouts at runtime instead of guessing.

That strictness is intentional for PKI/crypto safety.

### 1.1 Intentionally missing global DER knobs

Some "nice-to-have" global format options are intentionally not exposed.
This is deliberate, not an oversight.

In security-critical DER contexts, permissive decoder behavior often creates:
- silent downgrade/fallback paths
- acceptance of malformed or ambiguous encodings
- parser differentials between implementations
- forward-compat behavior that hides schema violations

Because of that, this codec intentionally does **not** provide global switches such as:
- `ignoreUnknownElements` / "best effort" trailing element skipping
- non-failing `unknownChoicePolicy` fallback modes for CHOICE
- `ambiguityPolicy = WARN/ALLOW` for undecidable nullable/optional layouts
- relaxed tag-mismatch behavior

Current behavior is intentionally strict:
- extra trailing children fail decode
- CHOICE requires exactly one matching arm
- ambiguous layouts fail fast
- tag mismatches fail fast

If you need compatibility variation, model it explicitly in schema/type design
(for example dedicated extension points, explicit wrappers, or disambiguating tags),
instead of a global permissive mode.

## 2. Baseline Mapping (No ASN.1 Annotations)

Without ASN.1 annotations, the default mapping is:
- `Boolean` -> `BOOLEAN`
- `Byte`/`Short`/`Int`/`Long` -> `INTEGER`
- `Float`/`Double` -> `REAL`
- `String`/`Char` -> ASN.1 string primitive
- `ByteArray` -> `OCTET STRING`
- `data class`/`object` -> `SEQUENCE`
- `List<T>`/`Map<K,V>` -> `SEQUENCE`
- `Set<T>` -> `SET`

Nullable default:
- `null` is omitted (no child emitted)

Example:

```kotlin
@Serializable
data class Person(
    val name: String,
    val age: Int,
)
```

Equivalent ASN.1 intent:

```asn1
Person ::= SEQUENCE {
  name UTF8String,
  age  INTEGER
}
```

## 3. Annotation Model (Split)

The old uber-annotation model has been split.

### 3.1 `@Asn1Tag`

Tag override only:

```kotlin
@Asn1Tag(
    tagNumber,
    tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    constructed = Asn1ConstructedBit.INFER,
)
```

- This is an IMPLICIT-style tag override.

### 3.2 `@Asn1Choice`

Enables ASN.1 CHOICE semantics for sealed polymorphism.
- no discriminator wrapper
- exactly one choice arm is encoded

### 3.3 `@Asn1BitString`

Marks `ByteArray` as `BIT STRING` instead of `OCTET STRING`.
- target is `PROPERTY` only
- hard-fails at runtime if used on non-`ByteArray`-compatible types

## 4. Annotation Precedence

For tag override (`@Asn1Tag`), precedence is:
1. inline/value-class hint
2. property annotation
3. class annotation

This is resolved independently for tag number, tag class, and constructed bit.

For marker annotations (`@Asn1Choice`, `@Asn1BitString`), property-level intent is what matters at field boundaries.

## 5. EXPLICIT and OCTET Modeling

There are no old `layers` anymore.

### 5.1 EXPLICIT tagging

Use `Asn1Explicit<T>` + an outer context-specific constructed tag.

```kotlin
@Serializable
data class TbsLike(
    @Asn1Tag(3u)
    val extensions: Asn1Explicit<List<MyExtension>>? = null,
)
```

Runtime enforces for `Asn1Explicit<T>`:
- effective tag must be `CONTEXT_SPECIFIC + CONSTRUCTED`

### 5.2 OCTET wrapping

Use `Asn1OctetWrapped<T>`.

```kotlin
@Serializable
data class Envelope(
    val payload: Asn1OctetWrapped<MyInnerType>
)
```

This models OCTET STRING encapsulation with inner encoded bytes as content.

## 6. Null Encoding and Ambiguity

### 6.1 Why ambiguity appears

If a nullable field is omitted, decoder must decide whether the next child is:
- still the nullable field (present), or
- the following field (nullable omitted)

When both can start with overlapping leading tags, layout is ambiguous.

### 6.2 Fixes

Use one of:
1. disambiguating tag overrides (`@Asn1Tag`)
2. explicit wrappers (`Asn1Explicit<T>`)
3. global explicit null encoding (`DER { explicitNulls = true }`) where safe
4. model shaping (e.g., defaults + `encodeDefaults = false`, secondary constructors, or schema-faithful wrappers)

### 6.3 Important caveat with `explicitNulls = true`

`explicitNulls = true` with IMPLICIT tagging can be ambiguous for some primitive bases.

The codec rejects ambiguous null-sentinel combinations, for example when null and a non-null empty value could become indistinguishable under the same implicit tag.

In short: explicit null encoding is useful, but not a free pass.

## 7. Optional Layout Checker

For class/object descriptors, the codec computes possible leading tags per field and verifies optional/nullable layout determinism.

It fails when:
- an omittable field overlaps leading tags with a reachable following field
- leading tags cannot be inferred for a non-trailing omittable field (undecidable)

This is checked in encode and decode paths.

### 7.1 Where leading tags come from

The checker tries these sources:
1. descriptor-derived defaults (primitive kinds, `SEQUENCE`/`SET`, `ByteArray`, etc.)
2. annotation effects (`@Asn1Tag`, `@Asn1BitString`, `@Asn1Choice`)
3. serializer-level contract from `Asn1Serializer.leadingTags`

That third source is important for custom serializers, where `SerialDescriptor` alone is not enough to infer wire-leading tags safely.

### 7.2 `Asn1Serializer.leadingTags` semantics

Every `Asn1Serializer` now declares:
- `leadingTags = setOf(...)` for exact known possible leading tags
- `leadingTags = emptySet()` when unknown/value-dependent

For non-`Asn1Serializer` custom serializers, expose the same contract by making the serializer descriptor implement `Asn1LeadingTagsDescriptor`.

Meaning:
- non-empty set -> checker treats tags as exact and can often prove determinism
- empty set -> checker treats field as unknown; middle nullable/optional fields may be rejected as ambiguous

Example (exact):

```kotlin
companion object : Asn1Serializer<Asn1Sequence, MyType> {
    override val leadingTags: Set<Asn1Element.Tag> = setOf(Asn1Element.Tag.SEQUENCE)
    // ...
}
```

Example (unknown):

```kotlin
companion object : Asn1Serializer<Asn1Element, MyExtensionPoint> {
    override val leadingTags: Set<Asn1Element.Tag> = emptySet()
    // ...
}
```

## 8. Polymorphism and CHOICE

### 8.1 Default polymorphism

Default kotlinx polymorphism behavior is not ASN.1 CHOICE. It carries type information via the normal polymorphic shape.

### 8.2 CHOICE mode

Use sealed hierarchy + `@Asn1Choice`.

```kotlin
@Serializable
@Asn1Choice
sealed interface SubjectAltName

@Serializable
data class DnsName(val value: String) : SubjectAltName

@Serializable
@Asn1Tag(tagNumber = 2u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
data class Rfc822Name(val value: String) : SubjectAltName
```

Rules:
- only sealed polymorphism is supported
- each arm must decode unambiguously
- if multiple arms match during decode, decode fails as ambiguous CHOICE

### 8.3 Why this CHOICE model (and not protobuf-style `oneof`)

We intentionally model CHOICE as sealed polymorphism (`@Asn1Choice`) instead of copying protobuf `oneof` shape.

Why:
- ASN.1 CHOICE has no discriminator field on the wire. Protobuf-style modeling is centered around field presence/index semantics and does not map naturally to DER tag-driven selection.
- CHOICE arms in real schemas can be arbitrarily complex (tagged wrappers, nested `SEQUENCE`, explicit wrappers). A sealed arm type can express that directly; a flat `oneof`-like wrapper quickly becomes rigid.
- We need runtime ambiguity detection at DER tag level. The current model can try all sealed arms, accept exactly one, and hard-fail on zero/multiple matches.
- Protobuf-style wrappers tend to push users toward nullable sibling fields (`a: A?`, `b: B?`, ...), which is exactly the class layout style that creates optional/nullable ambiguity problems in ASN.1.

Practical consequence:
- `@Asn1Choice` keeps CHOICE extensible for PKI/CMS-style schemas without introducing synthetic wire artifacts.
- It also keeps strict "no guesswork" semantics: unique arm match required, otherwise fail.

## 9. `@Asn1BitString` in Practice

### 9.1 Plain property

```kotlin
@Serializable
data class Sig(
    @Asn1BitString
    val bits: ByteArray
)
```

### 9.2 Value class pattern

`@Asn1BitString` is property-only, so annotate the inner `val`:

```kotlin
@JvmInline
@Serializable
value class KeyBits(
    @Asn1BitString
    val bytes: ByteArray
)
```

This is fully supported. Inline/value-class handling propagates that property annotation correctly.

### 9.3 Hard-fail behavior

If `@Asn1BitString` is applied in a way that resolves to a non-`ByteArray` serializer/value, serialization/deserialization throws `SerializationException`.

## 10. Maps, Sets, and Defaults

- Maps are supported (`SEQUENCE` encoding)
- Sets use ASN.1 `SET`
- Format config includes:
  - `encodeDefaults` (`DER { encodeDefaults = false }`)
  - `explicitNulls` (`DER { explicitNulls = true }`)

## 11. Custom Serializer Guidance

Custom serializers are allowed, but ambiguity checks still apply to containing class layouts.

Practical rule:
- if a field has unknown/non-inferable leading tags and is nullable/optional in the middle of a class, expect hard rejection unless you add disambiguation (tagging/wrapping/design change)
- if you write an `Asn1Serializer`, always set `leadingTags` accurately
- if you write a non-`Asn1Serializer` custom serializer, implement `Asn1LeadingTagsDescriptor` on its descriptor so ambiguity checks and tag-override inference can stay deterministic

For extension points, prefer explicit tagging/wrappers or trailing positions.

## 12. OID Open Polymorphism and `leadingTags`

This is the part that is easy to misunderstand.

For OID-discriminated open polymorphism, the registry needs two things per subtype:
1. OID mapping (decode dispatch and encode validation)
2. possible leading ASN.1 tag(s) (for ambiguity checks in containing models)

### 12.1 Strict registration API

The strict API uses the `IdentifiedBy` contract:

```kotlin
extensibleSerializer.registerSubtype(
    subtype = MySubtype::class,
    oidSource = MySubtype.Companion, // must be Identifiable
)
```

This is strict because:
- `MySubtype` must satisfy the serializer's base type `T`
- and `T` must be `IdentifiedBy<I>`
- and `oidSource` must be that exact `I` (not any random `Identifiable`)

So wrong source types fail at compile time.

### 12.2 Why `leadingTags` often do not need to be passed

In most cases, tags are inferred automatically from `serializer<MySubtype>().descriptor`.

Tag inference order:
1. serializer-declared ASN.1 leading tags metadata (for example `Asn1Serializer.leadingTags`)
2. descriptor kind fallback (primitive/class/list/map/sealed-choice rules)

So for normal `@Serializable` classes and normal `Asn1Serializer` companions, this works with no explicit tags argument.

### 12.3 When explicit `leadingTags` are still required

You must pass explicit tags when inference is unknown (`UnknownInfer`), for example:
- custom serializer with value-dependent wire shape
- serializer that intentionally declares `leadingTags = emptySet()`
- descriptor that does not expose enough structure for deterministic tag inference

Then use:

```kotlin
extensibleSerializer.registerSubtype(
    subtype = MyWeirdSubtype::class,
    oidSource = MyWeirdSubtype.Companion,
    Asn1Element.Tag.SEQUENCE,
    // add all possible leading tags here
)
```

If tags are omitted in such a case, registration fails fast with a clear error.

### 12.4 Concrete "works without tags" example

```kotlin
interface OpenByOidSource : Identifiable

@Serializable(with = OpenByOidSerializer::class)
interface OpenByOid : IdentifiedBy<OpenByOidSource>

@Serializable
data class OpenByOidInt(
    val value: Int
) : OpenByOid {
    companion object : OpenByOidSource {
        override val oid: ObjectIdentifier = ObjectIdentifier("1.2.840.113549.1.1.1")
    }

    override val oidSource: OpenByOidSource
        get() = Companion
}

object OpenByOidSerializer : Asn1OidDiscriminatedOpenPolymorphicSerializer<OpenByOid>(
    serialName = "OpenByOid",
    subtypes = listOf(
        asn1OpenPolymorphicSubtypeByOid<OpenByOid, OpenByOidInt>(
            serializer = OpenByOidInt.serializer(),
            oid = OpenByOidInt.Companion.oid,
            leadingTags = setOf(Asn1Element.Tag.SEQUENCE),
        )
    )
)

@Serializable
data class OpenByOidBool(
    val value: Boolean,
) : OpenByOid {
    companion object : OpenByOidSource {
        override val oid: ObjectIdentifier = ObjectIdentifier("1.3.101.110")
    }

    override val oidSource: OpenByOidSource
        get() = Companion
}

val extensibleSerializer = OpenByOidSerializer
extensibleSerializer.registerSubtype(
    subtype = OpenByOidBool::class,
    oidSource = OpenByOidBool.Companion
)
```

Here, `OpenByOidBool` is a normal class, so leading tag inference resolves to `SEQUENCE` and registration succeeds without explicit tags.

### 12.5 Concrete "must pass tags" example

```kotlin
object AnyDefinedBySerializer : KSerializer<MyAnyDefinedByType> {
    // descriptor/implementation intentionally value-dependent
    // no stable leading tag contract exposed
}

// This may fail because leading tags are unknown:
extensibleSerializer.registerSubtype(
    subtype = MyAnyDefinedByType::class,
    oidSource = MyAnyDefinedByType.Companion,
)

// Explicitly supply all possible leading tags instead:
extensibleSerializer.registerSubtype(
    subtype = MyAnyDefinedByType::class,
    oidSource = MyAnyDefinedByType.Companion,
    Asn1Element.Tag.SEQUENCE,
    Asn1Element.Tag.SET,
)
```

In other words: yes, there is a serializer tag-contract template already; explicit `leadingTags` are only needed when that contract is absent or intentionally unknown.

## 13. Quick Checklist

When modeling a schema:
1. Start with plain `@Serializable` types.
2. Add `@Asn1Tag` only where schema needs tag override.
3. Model EXPLICIT with `Asn1Explicit<T>` + context-specific constructed tag.
4. Model OCTET encapsulation with `Asn1OctetWrapped<T>`.
5. Use `@Asn1Choice` only for sealed CHOICE hierarchies.
6. Use `DER { explicitNulls = true }` only where needed, and watch for implicit-tag null ambiguity.
7. Use `@Asn1BitString` only on `ByteArray` properties.
8. Run serialization tests and treat ambiguity failures as modeling bugs, not decoder bugs.

## 14. Core Principle

No guesswork. If the layout is not provably deterministic from schema + annotations, the codec rejects it.
