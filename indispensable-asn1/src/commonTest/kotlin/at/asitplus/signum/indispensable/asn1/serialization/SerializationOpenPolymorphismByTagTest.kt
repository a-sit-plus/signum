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
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlin.jvm.JvmInline

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestOpenPolymorphismByTag by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Open-polymorphic tag dispatch round-trips with registered subtypes" {
        val intValue: OpenByTag = OpenByTagInt(7)
        val strValue: OpenByTag = OpenByTagString("hello")

        DER.decodeFromDer<OpenByTag>(DER.encodeToDer(intValue)) shouldBe intValue
        DER.decodeFromDer<OpenByTag>(DER.encodeToDer(strValue)) shouldBe strValue
    }

    "Unregistered subtype can be hooked by extending registrations" {
        val boolValue: OpenByTag = OpenByTagBool(true)
        val extensibleSerializer = createOpenByTagSerializer("OpenByTagExtensible")

        shouldThrow<SerializationException> {
            DER.encodeToDer(extensibleSerializer, boolValue)
        }.message.shouldContain("No registered open-polymorphic subtype")

        extensibleSerializer.registerSubtype(
            OpenByTagBool.serializer(),
            Asn1Element.Tag(
                tagValue = 2u,
                tagClass = TagClass.CONTEXT_SPECIFIC,
                constructed = false,
            ),
        )

        val encoded = DER.encodeToDer(extensibleSerializer, boolValue)
        DER.decodeFromDer(encoded, extensibleSerializer) shouldBe boolValue
    }

    "Nullable open-polymorphic property participates in ambiguity checks" {
        val ambiguous = NullableOpenByTagThenInt(
            first = null,
            second = 2,
        )
        shouldThrow<SerializationException> {
            DER.encodeToDer(ambiguous)
        }.message.shouldContain("Ambiguous ASN.1 layout")
    }

    "Leading tags stay visible on nullable open-polymorphic properties" {
        NullableOpenByTagThenInt.serializer().descriptor
            .getElementDescriptor(0)
            .asn1LeadingTagsOrNull shouldBe OpenByTagSerializer.leadingTags
    }

    "Tagging the sibling nullable property disambiguates layout" {
        val withoutFirst = NullableOpenByTagThenTaggedInt(
            first = null,
            second = 9,
        )
        val withFirst = NullableOpenByTagThenTaggedInt(
            first = OpenByTagInt(3),
            second = null,
        )
        DER.decodeFromDer<NullableOpenByTagThenTaggedInt>(DER.encodeToDer(withoutFirst)) shouldBe withoutFirst
        DER.decodeFromDer<NullableOpenByTagThenTaggedInt>(DER.encodeToDer(withFirst)) shouldBe withFirst
    }
}

@Serializable(with = OpenByTagSerializer::class)
interface OpenByTag

@Serializable
@JvmInline
value class OpenByTagInt(val value: Int) : OpenByTag

@Serializable
@Asn1Tag(tagNumber = 1u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, constructed = Asn1ConstructedBit.PRIMITIVE)
@JvmInline
value class OpenByTagString(val value: String) : OpenByTag

@Serializable
@Asn1Tag(tagNumber = 2u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, constructed = Asn1ConstructedBit.PRIMITIVE)
@JvmInline
value class OpenByTagBool(val value: Boolean) : OpenByTag

private fun createOpenByTagSerializer(
    serialName: String,
): Asn1TagDiscriminatedOpenPolymorphicSerializer<OpenByTag> =
    Asn1TagDiscriminatedOpenPolymorphicSerializer(
        serialName = serialName,
        subtypes = openByTagSubtypeRegistrations(),
    )

private fun openByTagSubtypeRegistrations() = listOf(
        asn1OpenPolymorphicSubtype<OpenByTag, OpenByTagInt>(
            serializer = OpenByTagInt.serializer(),
            leadingTags = setOf(Asn1Element.Tag.INT),
        ),
        asn1OpenPolymorphicSubtype<OpenByTag, OpenByTagString>(
            serializer = OpenByTagString.serializer(),
            leadingTags = setOf(
                Asn1Element.Tag(
                    tagValue = 1u,
                    tagClass = TagClass.CONTEXT_SPECIFIC,
                    constructed = false,
                )
            ),
        ),
    )

object OpenByTagSerializer : Asn1TagDiscriminatedOpenPolymorphicSerializer<OpenByTag>(
    serialName = "OpenByTag",
    subtypes = openByTagSubtypeRegistrations(),
)

@Serializable
data class NullableOpenByTagThenInt(
    val first: OpenByTag?,
    val second: Int?,
)

@Serializable
data class NullableOpenByTagThenTaggedInt(
    val first: OpenByTag?,
    @Asn1Tag(tagNumber = 42u)
    val second: Int?,
)
