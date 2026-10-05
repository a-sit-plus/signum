package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.Signum
import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.awesn1.serialization.encodeToTlv
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.decodeFromByteArray

import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe

private enum class StringKind { UTF8, PRINTABLE, IA5 }

private data class AttributeCase(
    val oid: String,
    val kind: StringKind,
    val names: Set<String>,
)

private val standardAttributes = listOf(
    AttributeCase("2.5.4.3", StringKind.UTF8, setOf("CN", "COMMONNAME")),
    AttributeCase("2.5.4.6", StringKind.PRINTABLE, setOf("C", "COUNTRY", "COUNTRYNAME")),
    AttributeCase("2.5.4.7", StringKind.UTF8, setOf("L", "LOCALITY", "LOCALITYNAME")),
    AttributeCase("2.5.4.8", StringKind.UTF8, setOf("ST", "S", "STATEORPROVINCENAME")),
    AttributeCase("2.5.4.9", StringKind.UTF8, setOf("STREET", "STREETADDRESS")),
    AttributeCase("2.5.4.10", StringKind.UTF8, setOf("O", "ORGANIZATION", "ORGANIZATIONNAME")),
    AttributeCase("2.5.4.11", StringKind.UTF8, setOf("OU", "ORGANIZATIONALUNIT", "ORGANIZATIONALUNITNAME")),
    AttributeCase("2.5.4.12", StringKind.UTF8, setOf("T", "TITLE")),
    AttributeCase("2.5.4.20", StringKind.PRINTABLE, setOf("TELEPHONENUMBER")),
    AttributeCase("2.5.4.4", StringKind.UTF8, setOf("SURNAME")),
    AttributeCase("2.5.4.5", StringKind.PRINTABLE, setOf("SERIALNUMBER")),
    AttributeCase("2.5.4.41", StringKind.UTF8, setOf("NAME")),
    AttributeCase("2.5.4.42", StringKind.UTF8, setOf("GIVENNAME")),
    AttributeCase("2.5.4.43", StringKind.UTF8, setOf("INITIALS")),
    AttributeCase("2.5.4.44", StringKind.UTF8, setOf("GENERATION")),
    AttributeCase("2.5.4.46", StringKind.PRINTABLE, setOf("DNQUALIFIER", "DNQ")),
    AttributeCase("0.9.2342.19200300.100.1.25", StringKind.IA5, setOf("DC")),
    AttributeCase("0.9.2342.19200300.100.1.1", StringKind.UTF8, setOf("UID")),
    AttributeCase("1.2.840.113549.1.9.1", StringKind.IA5, setOf("EMAILADDRESS", "EMAIL")),
)

val X500AttributeRegistryTest by matrixSuite {
    compact("standard X.500 shorthand registry") - {
        data(standardAttributes, nameFn = { it.names.first() }) - { case ->
            data(case.names) test { name ->
                val attribute = AttributeTypeAndValue.fromString(name.lowercase(), "Test")
                    as AttributeTypeAndValue
                val value = Asn1String.decodeFromTlv(attribute.value.asPrimitive())

                attribute::class shouldBe BaseX509AttributeTypeAndValue::class
                attribute.oid shouldBe ObjectIdentifier(case.oid)
                value.value shouldBe "Test"
                when (case.kind) {
                    StringKind.UTF8 -> (value is Asn1String.UTF8) shouldBe true
                    StringKind.PRINTABLE -> (value is Asn1String.Printable) shouldBe true
                    StringKind.IA5 -> (value is Asn1String.IA5) shouldBe true
                }
            }
        }
    }

    data(standardAttributes, nameFn = { "non-canonical ${it.names.first()}" }) test { case ->
        val nonCanonicalValue = when (case.kind) {
            StringKind.UTF8 -> Asn1String.Printable("Test")
            StringKind.PRINTABLE, StringKind.IA5 -> Asn1String.UTF8("Test")
        }.encodeToTlv()
        val original = RelativeDistinguishedName(
            AttributeTypeAndValue(ObjectIdentifier(case.oid), nonCanonicalValue)
        )
        val encoded = Signum.Der.encodeToByteArray(original)
        val decoded = Signum.Der.decodeFromByteArray<RelativeDistinguishedName>(encoded)
        val attribute = decoded.attrsAndValues.single() as AttributeTypeAndValue

        attribute::class shouldBe BaseX509AttributeTypeAndValue::class
        attribute.value shouldBe nonCanonicalValue
        Signum.Der.encodeToByteArray(decoded) shouldBe encoded
    }

    "unknown dotted OID falls back to UTF8" {
        val attribute = AttributeTypeAndValue.fromString("1.2.3.4", "Test")
            as AttributeTypeAndValue
        val value = Asn1String.decodeFromTlv(attribute.value.asPrimitive())

        attribute.oid shouldBe ObjectIdentifier("1.2.3.4")
        (value is Asn1String.UTF8) shouldBe true
        AttributeTypeAndValue.fromString("UNKNOWN", "Test") shouldBe null
    }
}
