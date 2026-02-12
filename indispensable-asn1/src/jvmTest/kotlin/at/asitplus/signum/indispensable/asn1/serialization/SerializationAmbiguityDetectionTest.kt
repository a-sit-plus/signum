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

    "Tag class is considered for ambiguity disambiguation" {
        val withoutTagged = ContextSpecificVsUniversalInt(null, 7)
        val withTagged = ContextSpecificVsUniversalInt(5, 7)

        DER.decodeFromDer<ContextSpecificVsUniversalInt>(DER.encodeToDer(withoutTagged)) shouldBe withoutTagged
        DER.decodeFromDer<ContextSpecificVsUniversalInt>(DER.encodeToDer(withTagged)) shouldBe withTagged
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
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 0uL))
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
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 10uL))
    val longValue: Long?,
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 11uL))
    val intValue: Int?,
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 12uL))
    val shortValue: Short?,
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 13uL))
    val byteValue: Byte?,
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 14uL))
    val floatValue: Float?,
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 15uL))
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
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 20uL))
    val longValue: Long?,
    val intValue: Int?,
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 21uL))
    val shortValue: Short?,
    val byteValue: Byte?,
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 22uL))
    val floatValue: Float?,
    val doubleValue: Double?,
)

@Serializable
data class PartiallyTaggedUnambiguousNumericNullables(
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 30uL))
    val longValue: Long?,
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 31uL))
    val intValue: Int?,
    val shortValue: Short?,
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 32uL))
    val byteValue: Byte?,
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 33uL))
    val floatValue: Float?,
    val doubleValue: Double?,
)

@Serializable
data class ContextSpecificVsUniversalInt(
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 2uL))
    val maybeTaggedInt: Int?,
    val plainInt: Int,
)
