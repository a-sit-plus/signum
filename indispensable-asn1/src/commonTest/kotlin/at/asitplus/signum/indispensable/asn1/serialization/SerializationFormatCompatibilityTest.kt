package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1Real
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

val SerializationTestFormatCompatibility by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Basic ASN.1 scalar serializers support non-ASN.1 formats" {
        val asn1String = Asn1String.UTF8("foo")
        Json.decodeFromString(
            Asn1String.Companion,
            Json.encodeToString(Asn1String.Companion, asn1String)
        ) shouldBe asn1String

        val asn1Integer = Asn1Integer(42)
        Json.decodeFromString(
            Asn1Integer.Companion,
            Json.encodeToString(Asn1Integer.Companion, asn1Integer)
        ) shouldBe asn1Integer

        val asn1Real = Asn1Real(3.25)
        Json.decodeFromString(
            Asn1Real.Companion,
            Json.encodeToString(Asn1Real.Companion, asn1Real)
        ) shouldBe asn1Real

        val oid = ObjectIdentifier("1.2.840.113549")
        Json.decodeFromString(
            ObjectIdentifier.Companion,
            Json.encodeToString(ObjectIdentifier.Companion, oid)
        ) shouldBe oid
    }

    "Complex ASN.1 serializers reject non-ASN.1 formats" {
        val value = RelativeDistinguishedName(
            AttributeTypeAndValue.CommonName(Asn1String.UTF8("CN"))
        )
        shouldThrow<SerializationException> {
            Json.encodeToString(RelativeDistinguishedName.Companion, value)
        }
        shouldThrow<SerializationException> {
            Json.decodeFromString(RelativeDistinguishedName.Companion, "\"irrelevant\"")
        }
    }
}
