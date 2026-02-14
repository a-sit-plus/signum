package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial10OpenPolyByTag by testSuite(
    testConfig = DefaultConfiguration
) {
    "Open polymorphism by leading tag" {
        val value: TutorialOpenByTag = TutorialOpenByTagInt(7)
        val der = DER.encodeToDer(value)
        der.toHexString() shouldBe "020107"
        DER.decodeFromDer<TutorialOpenByTag>(der) shouldBe value
    }
}

@Serializable(with = TutorialOpenByTagSerializer::class)
private interface TutorialOpenByTag

@Serializable
@JvmInline
private value class TutorialOpenByTagInt(
    val value: Int,
) : TutorialOpenByTag

private object TutorialOpenByTagSerializer : Asn1TagDiscriminatedOpenPolymorphicSerializer<TutorialOpenByTag>(
    serialName = "TutorialOpenByTag",
    subtypes = listOf(
        asn1OpenPolymorphicSubtype<TutorialOpenByTag, TutorialOpenByTagInt>(
            serializer = TutorialOpenByTagInt.serializer(),
            leadingTags = setOf(Asn1Element.Tag.INT),
        )
    ),
)
