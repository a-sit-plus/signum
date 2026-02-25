package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial08ExplicitNulls by testSuite(
    testConfig = DefaultConfiguration
) {
    "explicitNulls=true encodes null as ASN.1 NULL" {
        val format = DER { explicitNulls = true }
        val value = TutorialNullableInt(value = null)
        val der = format.encodeToDer(value)
        der.toHexString() shouldBe "30020500"
        format.decodeFromDer<TutorialNullableInt>(der) shouldBe value
    }
}

@Serializable
private data class TutorialNullableInt(
    val value: Int?,
)
