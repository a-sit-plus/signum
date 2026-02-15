package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.modules.SerializersModule


val SerializationTutorial11OpenPolyByOid by testSuite(
    testConfig = DefaultConfiguration
) {
    "Open polymorphism by OID" {
        val derCodec = DER {
            serializersModule = SerializersModule {
                polymorphicByOid(TutorialOpenByOid::class, serialName = "TutorialOpenByOid") {
                    subtype<TutorialOpenByOidInt>(TutorialOpenByOidInt)
                }
            }
        }

        val value: TutorialOpenByOid = TutorialOpenByOidInt(value = 9)
        derCodec.decodeFromDer<TutorialOpenByOid>("300e06092a864886f70d010101020109".hexToByteArray()) shouldBe value
        val der = derCodec.encodeToDer(value)
        der.toHexString() shouldBe "300e06092a864886f70d010101020109"
    }
}

private interface TutorialOpenByOid: Identifiable

@Serializable
private data class TutorialOpenByOidInt(
  //  val oid: ObjectIdentifier = tutorialOid,
    val value: Int,
) : TutorialOpenByOid,  Identifiable by Companion {
    companion object: Identifiable {
        override val oid: ObjectIdentifier = ObjectIdentifier("1.2.840.113549.1.1.1")

    }
}
