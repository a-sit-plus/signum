package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial06Choice by testSuite(
    testConfig = DefaultConfiguration
) {
    "Sealed CHOICE uses sealed polymorphism" - {
        "INT" {
            val value = (TutorialChoiceInt(7))
            val der = DER.encodeToDer(value)
            der.toHexString() shouldBe "3003020107"
            DER.decodeFromDer<TutorialChoice>(der) shouldBe value
        }
        "BOOL" {
            val value = (TutorialChoiceBool(true))
            val der = DER.encodeToDer(value)
            der.toHexString() shouldBe "bf8a39030101ff"
            DER.decodeFromDer<TutorialChoice>(der) shouldBe value
        }
    }
}

@Serializable
private sealed interface TutorialChoice

@Serializable
private data class TutorialChoiceInt(
    val value: Int,
) : TutorialChoice

@Serializable
@Asn1Tag(1337u)
private data class TutorialChoiceBool(
    val value: Boolean,
) : TutorialChoice
