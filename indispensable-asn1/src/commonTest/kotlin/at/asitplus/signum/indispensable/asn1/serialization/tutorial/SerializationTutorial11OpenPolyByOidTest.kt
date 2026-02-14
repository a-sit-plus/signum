package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.IdentifiedBy
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable

private val tutorialOid = ObjectIdentifier("1.2.840.113549.1.1.1")

val SerializationTutorial11OpenPolyByOid by testSuite(
    testConfig = DefaultConfiguration
) {
    "Open polymorphism by OID" {
        val value: TutorialOpenByOid = TutorialOpenByOidInt(value = 9)
        val der = DER.encodeToDer(value)
        der.toHexString() shouldBe "300e06092a864886f70d010101020109"
        DER.decodeFromDer<TutorialOpenByOid>(der) shouldBe value
    }
}

@Serializable(with = TutorialOpenByOidSerializer::class)
private interface TutorialOpenByOid : Identifiable, IdentifiedBy<ObjectIdentifier> {
    override val oidSource: ObjectIdentifier
        get() = oid
}

@Serializable
private data class TutorialOpenByOidInt(
    override val oid: ObjectIdentifier = tutorialOid,
    val value: Int,
) : TutorialOpenByOid {
    override val oidSource: ObjectIdentifier
        get() = oid
}

private object TutorialOpenByOidSerializer : Asn1OidDiscriminatedOpenPolymorphicSerializer<TutorialOpenByOid>(
    serialName = "TutorialOpenByOid",
    subtypes = listOf(
        asn1OpenPolymorphicSubtypeByOid<TutorialOpenByOid, TutorialOpenByOidInt>(
            serializer = TutorialOpenByOidInt.serializer(),
            oid = tutorialOid,
            leadingTags = setOf(Asn1Element.Tag.SEQUENCE),
        )
    ),
)
