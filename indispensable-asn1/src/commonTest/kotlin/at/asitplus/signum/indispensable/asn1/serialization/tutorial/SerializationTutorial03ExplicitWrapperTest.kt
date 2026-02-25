package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial03ExplicitWrapper by testSuite(
    testConfig = DefaultConfiguration
) {
    "EXPLICIT modeling with Asn1Explicit + context-specific constructed tag" {
        val value = TutorialExplicitCarrier(
            wrapped = ExplicitlyTagged(5),
        )
        val der = DER.encodeToDer(value)
        der.toHexString() shouldBe "3005a003020105"
        DER.decodeFromDer<TutorialExplicitCarrier>(der) shouldBe value
    }
}

@Serializable
private data class TutorialExplicitCarrier(
    @Asn1Tag(
        tagNumber = 0u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
        constructed = Asn1ConstructedBit.CONSTRUCTED,
    )
    val wrapped: ExplicitlyTagged<Int>,
)
