package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial02TagOverride by testSuite(
    testConfig = DefaultConfiguration
) {
    "Implicit tag override with @Asn1Tag" {
        val value = TutorialTaggedInt(value = 5)
        val der = DER.encodeToDer(value)
        der.toHexString() shouldBe "3003800105"
        DER.decodeFromDer<TutorialTaggedInt>(der) shouldBe value
    }
}

@Serializable
private data class TutorialTaggedInt(
    @Asn1Tag(
        tagNumber = 0u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
        constructed = Asn1ConstructedBit.PRIMITIVE,
    )
    val value: Int,
)
