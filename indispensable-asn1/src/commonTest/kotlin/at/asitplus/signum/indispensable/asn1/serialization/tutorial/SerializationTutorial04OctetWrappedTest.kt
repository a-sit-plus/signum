package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial04OctetWrapped by testSuite(
    testConfig = DefaultConfiguration
) {
    "OCTET STRING encapsulation with Asn1OctetWrapped" {
        val value = TutorialOctetCarrier(
            wrapped = OctetStringEncapsulated(5),
        )
        val der = DER.encodeToDer(value)
        der.toHexString() shouldBe "30050403020105"
        DER.decodeFromDer<TutorialOctetCarrier>(der) shouldBe value
    }
}

@Serializable
private data class TutorialOctetCarrier(
    val wrapped: OctetStringEncapsulated<Int>,
)
