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
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestCustomSerializerLeadingTags by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Custom serializer with unknown leadingTags is rejected in undecidable optional middle position" {
        val derNoDefaults = DER { encodeDefaults = false }
        val value = UnknownLeadingTagsOptionalMiddle(
            prefix = 1,
            suffix = 2,
        )

        shouldThrow<SerializationException> {
            derNoDefaults.encodeToDer(value)
        }
        shouldThrow<SerializationException> {
            derNoDefaults.decodeFromDer<UnknownLeadingTagsOptionalMiddle>("3006020101020102".hexToByteArray())
        }
    }

    "Custom serializer with exact leadingTags enables implicit tag override inference" {
        val derNoDefaults = DER { encodeDefaults = false }
        KnownLeadingTagsOptionalMiddle.serializer().descriptor
            .getElementAnnotations(1)
            .any { it is Asn1Tag } shouldBe true

        val omitted = KnownLeadingTagsOptionalMiddle(
            prefix = 1,
            extension = null,
            suffix = 2,
        )
        derNoDefaults.decodeFromDer<KnownLeadingTagsOptionalMiddle>(derNoDefaults.encodeToDer(omitted)) shouldBe omitted

        val present = KnownLeadingTagsOptionalMiddle(
            prefix = 1,
            extension = CustomLeadingTagsInt(99),
            suffix = 2,
        )

        val encoded = derNoDefaults.encodeToTlv(present).asStructure()
        val extensionTag = encoded.children[1].tag
        extensionTag.tagClass shouldBe TagClass.CONTEXT_SPECIFIC
        extensionTag.tagValue shouldBe 42UL
        extensionTag.isConstructed shouldBe false

        val encodedDer = derNoDefaults.encodeToDer(present)
        val reparsed = derNoDefaults.decodeFromDer<Asn1Element>(encodedDer).asStructure()
        val reparsedExtensionTag = reparsed.children[1].tag
        reparsedExtensionTag.tagClass shouldBe TagClass.CONTEXT_SPECIFIC
        reparsedExtensionTag.tagValue shouldBe 42UL
        reparsedExtensionTag.isConstructed shouldBe false

        derNoDefaults.decodeFromDer<KnownLeadingTagsOptionalMiddle>(encodedDer) shouldBe present
    }
}

data class CustomLeadingTagsInt(val value: Int)

private object UnknownLeadingTagsIntSerializer : KSerializer<CustomLeadingTagsInt> {
    private val baseDescriptor = PrimitiveSerialDescriptor("UnknownLeadingTagsInt", PrimitiveKind.INT)
    override val descriptor: SerialDescriptor = baseDescriptor.withAsn1LeadingTags(emptySet())

    override fun serialize(encoder: Encoder, value: CustomLeadingTagsInt) {
        encoder.encodeInt(value.value)
    }

    override fun deserialize(decoder: Decoder): CustomLeadingTagsInt =
        CustomLeadingTagsInt(decoder.decodeInt())
}

private object KnownLeadingTagsIntSerializer : KSerializer<CustomLeadingTagsInt> {
    private val baseDescriptor = PrimitiveSerialDescriptor("KnownLeadingTagsInt", PrimitiveKind.INT)
    override val descriptor: SerialDescriptor =
        baseDescriptor.withAsn1LeadingTags(setOf(Asn1Element.Tag.INT))

    override fun serialize(encoder: Encoder, value: CustomLeadingTagsInt) {
        encoder.encodeInt(value.value)
    }

    override fun deserialize(decoder: Decoder): CustomLeadingTagsInt =
        CustomLeadingTagsInt(decoder.decodeInt())
}

@Serializable
data class UnknownLeadingTagsOptionalMiddle(
    val prefix: Int,
    @property:Asn1Tag(tagNumber = 42u)
    @Serializable(with = UnknownLeadingTagsIntSerializer::class)
    val extension: CustomLeadingTagsInt = CustomLeadingTagsInt(-1),
    val suffix: Int,
)

@Serializable
data class KnownLeadingTagsOptionalMiddle(
    val prefix: Int,
    @property:Asn1Tag(tagNumber = 42u)
    @Serializable(with = KnownLeadingTagsIntSerializer::class)
    val extension: CustomLeadingTagsInt? = null,
    val suffix: Int,
)
