# ASN.1 DER + Kotlinx Serialization Tutorial (Current Model)

This tutorial is intentionally tied to executable tests so docs and behavior do not drift.

Every documented feature below has a dedicated, self-contained test file that:
- defines its own model types
- encodes/decodes with `DER`
- asserts DER hex and/or round-trip behavior

## Feature Index (Docs -> Executable Example)

- Baseline mapping without ASN.1 annotations:
  [`SerializationTutorial01BaselineTest.kt`](indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/tutorial/SerializationTutorial01BaselineTest.kt)
- Implicit tag override with `@Asn1Tag`:
  [`SerializationTutorial02TagOverrideTest.kt`](indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/tutorial/SerializationTutorial02TagOverrideTest.kt)
- EXPLICIT modeling with `Asn1Explicit<T>`:
  [`SerializationTutorial03ExplicitWrapperTest.kt`](indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/tutorial/SerializationTutorial03ExplicitWrapperTest.kt)
- OCTET STRING encapsulation with `Asn1OctetWrapped<T>`:
  [`SerializationTutorial04OctetWrappedTest.kt`](indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/tutorial/SerializationTutorial04OctetWrappedTest.kt)
- `@Asn1BitString` mapping for `ByteArray`:
  [`SerializationTutorial05BitStringTest.kt`](indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/tutorial/SerializationTutorial05BitStringTest.kt)
- Sealed CHOICE (default for sealed hierarchies):
  [`SerializationTutorial06ChoiceTest.kt`](indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/tutorial/SerializationTutorial06ChoiceTest.kt)
- Ambiguity rejection (nullable/optional layout):
  [`SerializationTutorial07AmbiguityRejectTest.kt`](indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/tutorial/SerializationTutorial07AmbiguityRejectTest.kt)
- `DER { explicitNulls = true }`:
  [`SerializationTutorial08ExplicitNullsTest.kt`](indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/tutorial/SerializationTutorial08ExplicitNullsTest.kt)
- `DER { encodeDefaults = false }`:
  [`SerializationTutorial09EncodeDefaultsTest.kt`](indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/tutorial/SerializationTutorial09EncodeDefaultsTest.kt)
- Open polymorphism by leading tag:
  [`SerializationTutorial10OpenPolyByTagTest.kt`](indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/tutorial/SerializationTutorial10OpenPolyByTagTest.kt)
- Open polymorphism by OID (DER module registration):
  [`SerializationTutorial11OpenPolyByOidTest.kt`](indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/tutorial/SerializationTutorial11OpenPolyByOidTest.kt)
- Default map/set structural mapping:
  [`SerializationTutorial12MapAndSetTest.kt`](indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/tutorial/SerializationTutorial12MapAndSetTest.kt)

## 1. Core Rules

- Codec is strict: no guessing for ambiguous layouts.
- `@Asn1Tag` is implicit tag override.
- EXPLICIT is modeled via wrapper (`Asn1Explicit<T>`) + outer context-specific constructed tag.
- OCTET STRING encapsulation is modeled via wrapper (`Asn1OctetWrapped<T>`).
- CHOICE is the default for sealed polymorphism (tag-dispatch, no discriminator wrapper).
- Ambiguous nullable/optional layouts hard-fail.

## 2. Annotation Surface

- `@Asn1Tag`: tag number/class/constructed override (implicit tagging model)
- `@Asn1BitString`: property-level `ByteArray` -> `BIT STRING`

## 3. Precedence and Shape

Tag override precedence is:
1. inline/value-class hint
2. property annotation
3. class annotation

For wrappers:
- `Asn1Explicit<T>` requires effective `CONTEXT_SPECIFIC + CONSTRUCTED` tag
- `Asn1OctetWrapped<T>` is encoded as universal primitive OCTET STRING containing encoded inner bytes

## 4. Ambiguity and Leading Tags

Ambiguity checker uses possible leading tags per field.
If an omittable field can overlap with reachable following fields, encoding/decoding is rejected.

Disambiguation options:
- add implicit tag overrides (`@Asn1Tag`)
- use explicit wrappers
- use `DER { explicitNulls = true }` where safe
- reshape model (defaults, wrappers, constructor strategy)

## 5. Polymorphism Modes

- CHOICE (sealed): exactly one matching arm must decode
- Open by tag: configure in `DER { serializersModule = SerializersModule { polymorphicByTag(...) } }`
- Open by OID: configure in `DER { serializersModule = SerializersModule { polymorphicByOid(...) } }`

**OID mode is tied to `Identifiable` / `OidProvider<Identifiable>` pair; registration is explicit and strict (OID + subtype + leading tags/inference):**  
Every polymorphic hierarchy identified by OID must be an `Identifiable` hierarchy with explicit registration.
A synthetic `ObjectIdentifier` is created as the first child node of an ASN.1 sequence during serialization and used for discrimination on deserialization. Be sure not to add a proper OID property! but ise a getter or delegate!  
See  [`SerializationTutorial11OpenPolyByOidTest.kt`](indispensable-asn1/src/commonTest/kotlin/at/asitplus/signum/indispensable/asn1/serialization/tutorial/SerializationTutorial11OpenPolyByOidTest.kt)

There is no shortcut for sealed OID-discriminated hierarchies for multiple reasons:
1. Signum's `ObjectIdentifier` is a powerful validating class, so we cannot add an `@Oid("1.2.43.4.3453.87.4.2")`.
2. There is `KnownOIDs` registry that comes with a gazillion OIDs, none of which could be referenced inside a hypothetical `@Oid` annotation
3. We want the OID to be accesssible from the code, not just serialization, typically from a Companion object on the identifiable-by-oid class.

## 6. DER Config Knobs

- `encodeDefaults`: include/omit default-valued properties
- `explicitNulls`: include/omit explicit ASN.1 NULL for nullable values
- `reEmitAsn1Backed`: serialize `Asn1Backed` values or re-emit deserialized ones

## 7. Running the Tutorial-backed Tests

Fast JVM run (covers all tutorial examples):

```bash
./gradlew :indispensable-asn1:jvmTest --tests "*SerializationTutorial*" --rerun-tasks
```

Broader serialization run:

```bash
./gradlew :indispensable-asn1:jvmTest --tests "at.asitplus.signum.indispensable.asn1.serialization*" --rerun-tasks
```

## 8. Why this strictness

DER + PKI/CMS/X.509 are security-sensitive.
Rejecting undecidable layouts and tag mismatches avoids parser differentials and silent schema drift.

If a schema needs more flexibility, model it explicitly in types/wrappers/serializers, not via permissive global decode behavior.
