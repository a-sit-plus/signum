package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.TagClass
import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestShapeContract by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "INFER works when runtime output matches descriptor-inferred tags" {
        val value = InferShapeNullableDynamicThenInt(
            first = DynamicPrimitiveValue("hello"),
            second = 23
        )
        DER.decodeFromDer<InferShapeNullableDynamicThenInt>(DER.encodeToDer(value)) shouldBe value
    }

    "INFER can fail for value-dependent custom serializers" {
        val value = InferShapeNullableDynamicThenInt(
            first = DynamicPrimitiveValue("7"),
            second = 23
        )
        val encoded = DER.encodeToDer(value)
        shouldThrow<SerializationException> {
            DER.decodeFromDer<InferShapeNullableDynamicThenInt>(encoded)
        }
    }

    "EXACT leading tags expose ambiguity early" {
        shouldThrow<SerializationException> {
            DER.encodeToDer(
                ExactShapeNullableDynamicThenInt(
                    first = DynamicPrimitiveValue("7"),
                    second = 23
                )
            )
        }
        shouldThrow<SerializationException> {
            DER.decodeFromDer<ExactShapeNullableDynamicThenInt>("3000".hexToByteArray())
        }
    }

    "VALUE_DEPENDENT rejects non-disambiguated nullable layout" {
        shouldThrow<SerializationException> {
            DER.encodeToDer(
                ValueDependentNullableDynamicThenInt(
                    first = DynamicPrimitiveValue("hello"),
                    second = 23
                )
            )
        }
        shouldThrow<SerializationException> {
            DER.decodeFromDer<ValueDependentNullableDynamicThenInt>("3000".hexToByteArray())
        }
    }

    "VALUE_DEPENDENT plus explicit tag is deterministic" {
        val nullFirst = ValueDependentExplicitNullableDynamicThenInt(
            first = null,
            second = 23
        )
        DER.decodeFromDer<ValueDependentExplicitNullableDynamicThenInt>(DER.encodeToDer(nullFirst)) shouldBe nullFirst

        val intFirst = ValueDependentExplicitNullableDynamicThenInt(
            first = DynamicPrimitiveValue("7"),
            second = 23
        )
        DER.decodeFromDer<ValueDependentExplicitNullableDynamicThenInt>(DER.encodeToDer(intFirst)) shouldBe intFirst

        val stringFirst = ValueDependentExplicitNullableDynamicThenInt(
            first = DynamicPrimitiveValue("hello"),
            second = 23
        )
        DER.decodeFromDer<ValueDependentExplicitNullableDynamicThenInt>(DER.encodeToDer(stringFirst)) shouldBe stringFirst
    }

    "Invalid VALUE_DEPENDENT shape declarations are rejected" {
        shouldThrow<SerializationException> {
            DER.encodeToDer(
                InvalidValueDependentShapeNullableDynamicThenInt(
                    first = DynamicPrimitiveValue("hello"),
                    second = 23
                )
            )
        }
    }
}

@Serializable(with = DynamicPrimitiveValueSerializer::class)
data class DynamicPrimitiveValue(
    val content: String
) 

object DynamicPrimitiveValueSerializer : KSerializer<DynamicPrimitiveValue> {
    override val descriptor: SerialDescriptor =
        buildClassSerialDescriptor("DynamicPrimitiveValue")

    override fun serialize(encoder: Encoder, value: DynamicPrimitiveValue) {
        val asInt = value.content.toIntOrNull()
        if (asInt != null) {
            encoder.encodeSerializableValue(Int.serializer(), asInt)
        } else {
            encoder.encodeSerializableValue(DynamicPrimitiveValueStringWrapper.serializer(), DynamicPrimitiveValueStringWrapper(value.content))
        }
    }

    override fun deserialize(decoder: Decoder): DynamicPrimitiveValue {
        return try {
            DynamicPrimitiveValue(decoder.decodeSerializableValue(Int.serializer()).toString())
        } catch (_: Throwable) {
            val wrapped = decoder.decodeSerializableValue(DynamicPrimitiveValueStringWrapper.serializer())
            DynamicPrimitiveValue(wrapped.content)
        }
    }
}

@Serializable
private data class DynamicPrimitiveValueStringWrapper(
    val content: String,
)

@Serializable
data class InferShapeNullableDynamicThenInt(
    val first: DynamicPrimitiveValue?,
    val second: Int,
)

@Serializable
data class ExactShapeNullableDynamicThenInt(
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
    val first: DynamicPrimitiveValue?,
    val second: Int,
)

@Serializable
data class ValueDependentNullableDynamicThenInt(
    @Asn1nnotation(
        shape = Asn1Shape(
            leadingTags = [Asn1LeadingTag(kind = Asn1LeadingTagKind.VALUE_DEPENDENT)]
        )
    )
    val first: DynamicPrimitiveValue?,
    val second: Int,
)

@Serializable
data class ValueDependentExplicitNullableDynamicThenInt(
    @Asn1nnotation(
        Layer(Type.EXPLICIT_TAG, 0uL),
        shape = Asn1Shape(
            leadingTags = [Asn1LeadingTag(kind = Asn1LeadingTagKind.VALUE_DEPENDENT)]
        )
    )
    val first: DynamicPrimitiveValue?,
    val second: Int,
)

@Serializable
data class InvalidValueDependentShapeNullableDynamicThenInt(
    @Asn1nnotation(
        shape = Asn1Shape(
            leadingTags = [
                Asn1LeadingTag(kind = Asn1LeadingTagKind.VALUE_DEPENDENT),
                Asn1LeadingTag(
                    kind = Asn1LeadingTagKind.TAG,
                    tagClass = TagClass.UNIVERSAL,
                    tag = 2uL,
                    constructed = Asn1ConstructedBit.PRIMITIVE,
                ),
            ]
        )
    )
    val first: DynamicPrimitiveValue?,
    val second: Int,
)
