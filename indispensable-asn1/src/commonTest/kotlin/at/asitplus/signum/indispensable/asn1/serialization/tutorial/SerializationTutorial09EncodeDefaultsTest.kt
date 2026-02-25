package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial09EncodeDefaults by testSuite(
    testConfig = DefaultConfiguration
) {
    "encodeDefaults=false omits default-valued properties" {
        val format = DER { encodeDefaults = false }
        val value = TutorialDefaults()
        val der = format.encodeToDer(value)
        der.toHexString() shouldBe "3000"
        format.decodeFromDer<TutorialDefaults>(der) shouldBe value
    }
}

@Serializable
private data class TutorialDefaults(
    val first: Int = 1,
    val second: Boolean = true,
)
