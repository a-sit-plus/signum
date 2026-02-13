package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestAmbiguityDetection by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Generic nullable ambiguity is rejected at runtime" {
        val ambiguous = AmbiguousNullableStringLayout("first", null, "third")
        shouldThrow<SerializationException> {
            DER.encodeToDer(ambiguous)
        }
        shouldThrow<SerializationException> {
            DER.decodeFromDer<AmbiguousNullableStringLayout>("300e0c0566697273740c057468697264".hexToByteArray())
        }
    }

    "Tagged nullable layouts remain valid" {
        val valueWithoutSecond = TaggedNullableStringLayout("first", null, "third")
        val valueWithSecond = TaggedNullableStringLayout("first", "second", "third")

        DER.decodeFromDer<TaggedNullableStringLayout>(DER.encodeToDer(valueWithoutSecond)) shouldBe valueWithoutSecond
        DER.decodeFromDer<TaggedNullableStringLayout>(DER.encodeToDer(valueWithSecond)) shouldBe valueWithSecond
    }

    "Consecutive nullable numeric fields are ambiguous without tags" {
        val value = ConsecutiveNumericNullables(
            longValue = 7L,
            intValue = null,
            shortValue = 3,
            byteValue = null,
            floatValue = null,
            doubleValue = 1.0
        )

        shouldThrow<SerializationException> {
            DER.encodeToDer(value)
        }
        shouldThrow<SerializationException> {
            DER.decodeFromDer<ConsecutiveNumericNullables>("3000".hexToByteArray())
        }
    }

    "Consecutive nullable numeric fields can be disambiguated with tags" {
        val mostlyNull = TaggedConsecutiveNumericNullables(
            longValue = null,
            intValue = 9,
            shortValue = null,
            byteValue = 2,
            floatValue = null,
            doubleValue = 3.5
        )
        val mostlySet = TaggedConsecutiveNumericNullables(
            longValue = 11L,
            intValue = 10,
            shortValue = 9,
            byteValue = 8,
            floatValue = 7.5f,
            doubleValue = 6.25
        )

        DER.decodeFromDer<TaggedConsecutiveNumericNullables>(DER.encodeToDer(mostlyNull)) shouldBe mostlyNull
        DER.decodeFromDer<TaggedConsecutiveNumericNullables>(DER.encodeToDer(mostlySet)) shouldBe mostlySet
    }

    "Consecutive nullable numeric fields can be disambiguated with explicit tags" {
        val mostlyNull = ExplicitTaggedConsecutiveNumericNullables(
            longValue = null,
            intValue = 9,
            shortValue = null,
            byteValue = 2,
            floatValue = null,
            doubleValue = 3.5
        )
        val mostlySet = ExplicitTaggedConsecutiveNumericNullables(
            longValue = 11L,
            intValue = 10,
            shortValue = 9,
            byteValue = 8,
            floatValue = 7.5f,
            doubleValue = 6.25
        )

        DER.decodeFromDer<ExplicitTaggedConsecutiveNumericNullables>(DER.encodeToDer(mostlyNull)) shouldBe mostlyNull
        DER.decodeFromDer<ExplicitTaggedConsecutiveNumericNullables>(DER.encodeToDer(mostlySet)) shouldBe mostlySet
    }

    "Consecutive nullable fields with distinct ASN.1 primitive kinds are unambiguous without tags" {
        val value = ConsecutiveDistinctNullableKinds(
            intValue = 3,
            boolValue = null,
            floatValue = 1.25f,
            stringValue = "ok"
        )
        DER.decodeFromDer<ConsecutiveDistinctNullableKinds>(DER.encodeToDer(value)) shouldBe value
    }

    "Partially tagged nullable numeric fields can still be ambiguous" {
        val value = PartiallyTaggedAmbiguousNumericNullables(
            longValue = 1L,
            intValue = null,
            shortValue = 2,
            byteValue = null,
            floatValue = 3.5f,
            doubleValue = null
        )

        shouldThrow<SerializationException> {
            DER.encodeToDer(value)
        }
        shouldThrow<SerializationException> {
            DER.decodeFromDer<PartiallyTaggedAmbiguousNumericNullables>("3000".hexToByteArray())
        }
    }

    "Partially explicit-tagged nullable numeric fields can still be ambiguous" {
        val value = PartiallyExplicitTaggedAmbiguousNumericNullables(
            longValue = 1L,
            intValue = null,
            shortValue = 2,
            byteValue = null,
            floatValue = 3.5f,
            doubleValue = null
        )

        shouldThrow<SerializationException> {
            DER.encodeToDer(value)
        }
        shouldThrow<SerializationException> {
            DER.decodeFromDer<PartiallyExplicitTaggedAmbiguousNumericNullables>("3000".hexToByteArray())
        }
    }

    "Partially tagged nullable numeric fields can be unambiguous" {
        val mostlyNull = PartiallyTaggedUnambiguousNumericNullables(
            longValue = null,
            intValue = 10,
            shortValue = null,
            byteValue = 3,
            floatValue = null,
            doubleValue = 2.25
        )
        val mostlySet = PartiallyTaggedUnambiguousNumericNullables(
            longValue = 12L,
            intValue = 11,
            shortValue = 10,
            byteValue = 9,
            floatValue = 8.75f,
            doubleValue = 7.5
        )

        DER.decodeFromDer<PartiallyTaggedUnambiguousNumericNullables>(DER.encodeToDer(mostlyNull)) shouldBe mostlyNull
        DER.decodeFromDer<PartiallyTaggedUnambiguousNumericNullables>(DER.encodeToDer(mostlySet)) shouldBe mostlySet
    }

    "Partially explicit-tagged nullable numeric fields can be unambiguous" {
        val mostlyNull = PartiallyExplicitTaggedUnambiguousNumericNullables(
            longValue = null,
            intValue = 10,
            shortValue = null,
            byteValue = 3,
            floatValue = null,
            doubleValue = 2.25
        )
        val mostlySet = PartiallyExplicitTaggedUnambiguousNumericNullables(
            longValue = 12L,
            intValue = 11,
            shortValue = 10,
            byteValue = 9,
            floatValue = 8.75f,
            doubleValue = 7.5
        )

        DER.decodeFromDer<PartiallyExplicitTaggedUnambiguousNumericNullables>(DER.encodeToDer(mostlyNull)) shouldBe mostlyNull
        DER.decodeFromDer<PartiallyExplicitTaggedUnambiguousNumericNullables>(DER.encodeToDer(mostlySet)) shouldBe mostlySet
    }

    "Tag class is considered for ambiguity disambiguation" {
        val withoutTagged = ContextSpecificVsUniversalInt(null, 7)
        val withTagged = ContextSpecificVsUniversalInt(5, 7)

        DER.decodeFromDer<ContextSpecificVsUniversalInt>(DER.encodeToDer(withoutTagged)) shouldBe withoutTagged
        DER.decodeFromDer<ContextSpecificVsUniversalInt>(DER.encodeToDer(withTagged)) shouldBe withTagged
    }

    "Class-level tags participate in ambiguity detection" {
        val ambiguous = NullablePlainIntBoxThenPlainIntBox(
            first = null,
            second = PlainIntBox(7)
        )
        shouldThrow<SerializationException> {
            DER.encodeToDer(ambiguous)
        }
        shouldThrow<SerializationException> {
            DER.decodeFromDer<NullablePlainIntBoxThenPlainIntBox>("3000".hexToByteArray())
        }

        val taggedWithoutFirst = NullableClassTaggedIntBoxes(
            first = null,
            second = ClassTaggedIntBoxB(7)
        )
        val taggedWithFirst = NullableClassTaggedIntBoxes(
            first = ClassTaggedIntBoxA(5),
            second = ClassTaggedIntBoxB(7)
        )

        DER.decodeFromDer<NullableClassTaggedIntBoxes>(DER.encodeToDer(taggedWithoutFirst)) shouldBe taggedWithoutFirst
        DER.decodeFromDer<NullableClassTaggedIntBoxes>(DER.encodeToDer(taggedWithFirst)) shouldBe taggedWithFirst
    }

    "Mixed property and class-level tags can still be ambiguous" {
        val ambiguous = NullableMixedTagLayeringStillAmbiguous(
            first = null,
            second = ClassImplicitIntBoxB(9)
        )
        shouldThrow<SerializationException> {
            DER.encodeToDer(ambiguous)
        }
        shouldThrow<SerializationException> {
            DER.decodeFromDer<NullableMixedTagLayeringStillAmbiguous>("3000".hexToByteArray())
        }
    }

    "Mixed property and class-level tags can disambiguate nullable fields" {
        val withoutFirst = NullableMixedTagLayeringDisambiguated(
            first = null,
            second = ClassImplicitIntBoxB(9)
        )
        val withFirst = NullableMixedTagLayeringDisambiguated(
            first = ClassImplicitIntBoxA(3),
            second = ClassImplicitIntBoxB(9)
        )

        DER.decodeFromDer<NullableMixedTagLayeringDisambiguated>(DER.encodeToDer(withoutFirst)) shouldBe withoutFirst
        DER.decodeFromDer<NullableMixedTagLayeringDisambiguated>(DER.encodeToDer(withFirst)) shouldBe withFirst
    }

    "Property implicit and class explicit layering works with nullable fields" {
        val withoutFirst = NullablePropertyImplicitClassExplicit(
            first = null,
            second = ClassExplicitIntBox(5)
        )
        val withFirst = NullablePropertyImplicitClassExplicit(
            first = ClassExplicitIntBox(4),
            second = ClassExplicitIntBox(5)
        )

        DER.decodeFromDer<NullablePropertyImplicitClassExplicit>(DER.encodeToDer(withoutFirst)) shouldBe withoutFirst
        DER.decodeFromDer<NullablePropertyImplicitClassExplicit>(DER.encodeToDer(withFirst)) shouldBe withFirst
    }

    "encodeNull=true on nullable properties removes omission ambiguity" {
        val ambiguous = NullableIntThenIntAmbiguous(
            first = null,
            second = 7
        )
        shouldThrow<SerializationException> {
            DER.encodeToDer(ambiguous)
        }
        shouldThrow<SerializationException> {
            DER.decodeFromDer<NullableIntThenIntAmbiguous>("3000".hexToByteArray())
        }

        val propertyEncodedNull = NullableIntThenIntPropertyEncodeNull(
            first = null,
            second = 7
        )
        val propertyEncodedSet = NullableIntThenIntPropertyEncodeNull(
            first = 5,
            second = 7
        )

        DER.decodeFromDer<NullableIntThenIntPropertyEncodeNull>(DER.encodeToDer(propertyEncodedNull)) shouldBe propertyEncodedNull
        DER.decodeFromDer<NullableIntThenIntPropertyEncodeNull>(DER.encodeToDer(propertyEncodedSet)) shouldBe propertyEncodedSet
    }

    "encodeNull=true on class-level annotations removes omission ambiguity" {
        val ambiguous = NullablePlainObjectThenPlainIntBox(
            first = null,
            second = PlainIntBox(7)
        )
        shouldThrow<SerializationException> {
            DER.encodeToDer(ambiguous)
        }
        shouldThrow<SerializationException> {
            DER.decodeFromDer<NullablePlainObjectThenPlainIntBox>("3000".hexToByteArray())
        }

        val classEncodedNull = NullableClassEncodedNullObjectThenPlainIntBox(
            first = null,
            second = PlainIntBox(7)
        )
        val classEncodedSet = NullableClassEncodedNullObjectThenPlainIntBox(
            first = ClassEncodedNullObject,
            second = PlainIntBox(7)
        )

        DER.decodeFromDer<NullableClassEncodedNullObjectThenPlainIntBox>(DER.encodeToDer(classEncodedNull)) shouldBe classEncodedNull
        DER.decodeFromDer<NullableClassEncodedNullObjectThenPlainIntBox>(DER.encodeToDer(classEncodedSet)) shouldBe classEncodedSet
    }
}

@Serializable
data class AmbiguousNullableStringLayout(
    val first: String,
    val second: String?,
    val third: String,
)

@Serializable
data class TaggedNullableStringLayout(
    val first: String,
    @Asn1nnotation(tagNumber = 0, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val second: String?,
    val third: String,
)

@Serializable
data class ConsecutiveNumericNullables(
    val longValue: Long?,
    val intValue: Int?,
    val shortValue: Short?,
    val byteValue: Byte?,
    val floatValue: Float?,
    val doubleValue: Double?,
)

@Serializable
data class TaggedConsecutiveNumericNullables(
    @Asn1nnotation(tagNumber = 10, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val longValue: Long?,
    @Asn1nnotation(tagNumber = 11, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val intValue: Int?,
    @Asn1nnotation(tagNumber = 12, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val shortValue: Short?,
    @Asn1nnotation(tagNumber = 13, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val byteValue: Byte?,
    @Asn1nnotation(tagNumber = 14, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val floatValue: Float?,
    @Asn1nnotation(tagNumber = 15, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val doubleValue: Double?,
)

@Serializable
data class ExplicitTaggedConsecutiveNumericNullables(
    @Asn1nnotation(tagNumber = 50, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val longValue: Long?,
    @Asn1nnotation(tagNumber = 51, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val intValue: Int?,
    @Asn1nnotation(tagNumber = 52, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val shortValue: Short?,
    @Asn1nnotation(tagNumber = 53, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val byteValue: Byte?,
    @Asn1nnotation(tagNumber = 54, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val floatValue: Float?,
    @Asn1nnotation(tagNumber = 55, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val doubleValue: Double?,
)

@Serializable
data class ConsecutiveDistinctNullableKinds(
    val intValue: Int?,
    val boolValue: Boolean?,
    val floatValue: Float?,
    val stringValue: String?,
)

@Serializable
data class PartiallyTaggedAmbiguousNumericNullables(
    @Asn1nnotation(tagNumber = 20, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val longValue: Long?,
    val intValue: Int?,
    @Asn1nnotation(tagNumber = 21, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val shortValue: Short?,
    val byteValue: Byte?,
    @Asn1nnotation(tagNumber = 22, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val floatValue: Float?,
    val doubleValue: Double?,
)

@Serializable
data class PartiallyExplicitTaggedAmbiguousNumericNullables(
    @Asn1nnotation(tagNumber = 60, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val longValue: Long?,
    val intValue: Int?,
    @Asn1nnotation(tagNumber = 61, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val shortValue: Short?,
    val byteValue: Byte?,
    @Asn1nnotation(tagNumber = 62, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val floatValue: Float?,
    val doubleValue: Double?,
)

@Serializable
data class PartiallyTaggedUnambiguousNumericNullables(
    @Asn1nnotation(tagNumber = 30, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val longValue: Long?,
    @Asn1nnotation(tagNumber = 31, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val intValue: Int?,
    val shortValue: Short?,
    @Asn1nnotation(tagNumber = 32, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val byteValue: Byte?,
    @Asn1nnotation(tagNumber = 33, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val floatValue: Float?,
    val doubleValue: Double?,
)

@Serializable
data class PartiallyExplicitTaggedUnambiguousNumericNullables(
    @Asn1nnotation(tagNumber = 70, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val longValue: Long?,
    @Asn1nnotation(tagNumber = 71, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val intValue: Int?,
    val shortValue: Short?,
    @Asn1nnotation(tagNumber = 72, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val byteValue: Byte?,
    @Asn1nnotation(tagNumber = 73, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val floatValue: Float?,
    val doubleValue: Double?,
)

@Serializable
data class ContextSpecificVsUniversalInt(
    @Asn1nnotation(tagNumber = 2, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val maybeTaggedInt: Int?,
    val plainInt: Int,
)

@Serializable
data class PlainIntBox(val value: Int)

@Serializable
@Asn1nnotation(tagNumber = 80, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
data class ClassTaggedIntBoxA(val value: Int)

@Serializable
@Asn1nnotation(tagNumber = 81, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
data class ClassTaggedIntBoxB(val value: Int)

@Serializable
data class NullablePlainIntBoxThenPlainIntBox(
    val first: PlainIntBox?,
    val second: PlainIntBox,
)

@Serializable
data class NullableClassTaggedIntBoxes(
    val first: ClassTaggedIntBoxA?,
    val second: ClassTaggedIntBoxB,
)

@Serializable
@Asn1nnotation(tagNumber = 90, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
data class ClassImplicitIntBoxA(val value: Int)

@Serializable
@Asn1nnotation(tagNumber = 91, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
data class ClassImplicitIntBoxB(val value: Int)

@Serializable
data class NullableMixedTagLayeringStillAmbiguous(
    @Asn1nnotation(tagNumber = 100, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val first: ClassImplicitIntBoxA?,
    @Asn1nnotation(tagNumber = 100, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val second: ClassImplicitIntBoxB,
)

@Serializable
data class NullableMixedTagLayeringDisambiguated(
    @Asn1nnotation(tagNumber = 100, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val first: ClassImplicitIntBoxA?,
    @Asn1nnotation(tagNumber = 101, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val second: ClassImplicitIntBoxB,
)

@Serializable
@Asn1nnotation(tagNumber = 110, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
data class ClassExplicitIntBox(val value: Int)

@Serializable
data class NullablePropertyImplicitClassExplicit(
    @Asn1nnotation(tagNumber = 111, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val first: ClassExplicitIntBox?,
    @Asn1nnotation(tagNumber = 112, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val second: ClassExplicitIntBox,
)

@Serializable
data class NullableIntThenIntAmbiguous(
    val first: Int?,
    val second: Int,
)

@Serializable
data class NullableIntThenIntPropertyEncodeNull(
    @Asn1nnotation(encodeNull = true)
    val first: Int?,
    val second: Int,
)

@Serializable
object PlainObject

@Serializable
@Asn1nnotation(encodeNull = true)
object ClassEncodedNullObject

@Serializable
data class NullablePlainObjectThenPlainIntBox(
    val first: PlainObject?,
    val second: PlainIntBox,
)

@Serializable
data class NullableClassEncodedNullObjectThenPlainIntBox(
    val first: ClassEncodedNullObject?,
    val second: PlainIntBox,
)
