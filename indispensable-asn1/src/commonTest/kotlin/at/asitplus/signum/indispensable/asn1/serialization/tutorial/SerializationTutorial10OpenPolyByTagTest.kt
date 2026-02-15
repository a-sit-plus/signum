package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.modules.SerializersModule
import kotlin.jvm.JvmInline

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial10OpenPolyByTag by testSuite(
    testConfig = DefaultConfiguration
) {
    "Open polymorphism by leading tag" - {
        val derCodec = DER {
            serializersModule = SerializersModule {
                polymorphicByTag(TutorialOpenByTag::class, serialName = "TutorialOpenByTag") {
                    subtype<TutorialOpenByTagInt>()
                    subtype<TutorialOpenByTagBool>()
                    subtype<TutorialOpenByTagSeqNoInline>()
                    subtype<TutorialOpenByTagSeqNoInlineManuallyTagged>()
                }
            }
        }

        "INT value class" {
            val value: TutorialOpenByTag = TutorialOpenByTagInt(7)
            val der = derCodec.encodeToDer(value)
            der.toHexString() shouldBe "020107"
            derCodec.decodeFromDer<TutorialOpenByTag>(der) shouldBe value
        }

        "BOOL value class" {
            val value: TutorialOpenByTag = TutorialOpenByTagBool(true)
            val der = derCodec.encodeToDer(value)
            der.toHexString() shouldBe "0101ff"
            derCodec.decodeFromDer<TutorialOpenByTag>(der) shouldBe value
        }

        "SEQUENCE regular class" {
            val value: TutorialOpenByTag = TutorialOpenByTagSeqNoInline(true)
            val der = derCodec.encodeToDer(value)
            der.toHexString() shouldBe "30030101ff"
            derCodec.decodeFromDer<TutorialOpenByTag>(der) shouldBe value
        }

        "SEQUENCE manually tagged" {
            val value: TutorialOpenByTag = TutorialOpenByTagSeqNoInlineManuallyTagged(false)
            val der = derCodec.encodeToDer(value)
            der.toHexString() shouldBe "bf6303010100"
            derCodec.decodeFromDer<TutorialOpenByTag>(der) shouldBe value
        }

    }
}

private interface TutorialOpenByTag

@Serializable
@JvmInline
private value class TutorialOpenByTagInt(
    val value: Int,
) : TutorialOpenByTag
@Serializable
@JvmInline
private value class TutorialOpenByTagBool(
    val value: Boolean,
) : TutorialOpenByTag

@Serializable
private data class TutorialOpenByTagSeqNoInline(
    val value: Boolean,
) : TutorialOpenByTag

@Asn1Tag(99u)
@Serializable
private data class TutorialOpenByTagSeqNoInlineManuallyTagged(
    val value: Boolean,
) : TutorialOpenByTag
