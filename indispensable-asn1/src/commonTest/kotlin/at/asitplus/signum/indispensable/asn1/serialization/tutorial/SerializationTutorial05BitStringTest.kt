package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.Serializable

@OptIn(ExperimentalStdlibApi::class)
val SerializationTutorial05BitString by testSuite(
    testConfig = DefaultConfiguration
) {
    "BIT STRING mapping with @Asn1BitString on ByteArray" {
        val value = TutorialBitStringCarrier(byteArrayOf(0xAA.toByte()))
        val der = DER.encodeToDer(value)
        der.toHexString() shouldBe "3004030200aa"
        val decoded = DER.decodeFromDer<TutorialBitStringCarrier>(der)
        decoded shouldNotBe value
        decoded.bits.contentToString() shouldBe value.bits.contentToString()
    }
}

@Serializable
private data class TutorialBitStringCarrier(
    @Asn1BitString
    val bits: ByteArray,
)
