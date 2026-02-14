package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial12MapAndSet by testSuite(
    testConfig = DefaultConfiguration
) {
    "Map and Set default mappings" {
        val value = TutorialMapAndSet(
            map = mapOf(1 to 2),
            set = setOf(3),
        )
        val der = DER.encodeToDer(value)
        der.toHexString() shouldBe "300d30060201010201023103020103"
        DER.decodeFromDer<TutorialMapAndSet>(der) shouldBe value
    }
}

@Serializable
private data class TutorialMapAndSet(
    val map: Map<Int, Int>,
    val set: Set<Int>,
)
