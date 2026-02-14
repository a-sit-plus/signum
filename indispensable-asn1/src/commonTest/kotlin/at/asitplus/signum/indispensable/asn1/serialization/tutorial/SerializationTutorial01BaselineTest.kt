package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial01Baseline by testSuite(
    testConfig = DefaultConfiguration
) {
    "Baseline mapping without ASN.1 annotations" {
        val value = TutorialPerson(name = "A", age = 5)
        val der = DER.encodeToDer(value)
        der.toHexString() shouldBe "30060c0141020105"
        DER.decodeFromDer<TutorialPerson>(der) shouldBe value
    }
}

@Serializable
private data class TutorialPerson(
    val name: String,
    val age: Int,
)
