package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial06Choice by testSuite(
    testConfig = DefaultConfiguration
) {
    "Sealed CHOICE with @Asn1Choice" {
        val value = TutorialChoiceContainer(TutorialChoiceInt(7))
        val der = DER.encodeToDer(value)
        der.toHexString() shouldBe "30053003020107"
        DER.decodeFromDer<TutorialChoiceContainer>(der) shouldBe value
    }
}

@Serializable
private data class TutorialChoiceContainer(
    val value: TutorialChoice,
)

@Serializable
@Asn1Choice
private sealed interface TutorialChoice

@Serializable
private data class TutorialChoiceInt(
    val value: Int,
) : TutorialChoice
