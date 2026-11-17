@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.sourceFormat
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

private enum class StringKind { UTF8, PRINTABLE, IA5 }

private data class AttributeCase(
    val oid: String,
    val kind: StringKind,
    val names: Set<String>,
    val text: String = "Test",
)

private val standardAttributes = listOf(
    AttributeCase("2.5.4.3", StringKind.UTF8, setOf("CN", "COMMONNAME")),
    AttributeCase("2.5.4.6", StringKind.PRINTABLE, setOf("C", "COUNTRY", "COUNTRYNAME"), "AT"),
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

val X500AttributeProviderTest by matrixSuite {
    compact("standard X.500 shorthand providers") - {
        data(standardAttributes, nameFn = { it.names.first() }) - { case ->
            data(case.names) test { name ->
                val attribute = AttributeTypeAndValue.fromString(name.lowercase(), case.text)
                    as AttributeTypeAndValue
                val value = Asn1String.decodeFromTlv(attribute.asn1.toRepresentation().value.asPrimitive())
                attribute.oid shouldBe ObjectIdentifier(case.oid)
                value.value shouldBe case.text
                when (case.kind) {
                    StringKind.UTF8 -> (value is Asn1String.UTF8) shouldBe true
                    StringKind.PRINTABLE -> (value is Asn1String.Printable) shouldBe true
                    StringKind.IA5 -> (value is Asn1String.IA5) shouldBe true
                }
            }
        }
    }

    data(standardAttributes, nameFn = { "alternate string tag ${it.names.first()}" }) test { case ->
        val encodedValue = when (case.kind) {
            StringKind.UTF8 -> Asn1String.Printable(case.text)
            StringKind.PRINTABLE, StringKind.IA5 -> Asn1String.UTF8(case.text)
        }.encodeToTlv()
        val original = RelativeDistinguishedName(
            AttributeTypeAndValue.fromAsn1(X500AttributeTypeAndValue(ObjectIdentifier(case.oid), encodedValue))
        )
        val encoded = original.asn1.toDer()
        val decoded = RelativeDistinguishedName.fromAsn1(encoded)
        val attribute = decoded.attrsAndValues.single().shouldBeInstanceOf<TextAttributeTypeAndValue>()
        attribute.text shouldBe case.text
        attribute.asn1.toRepresentation().value shouldBe encodedValue
        decoded.asn1.toDer() shouldBe encoded
    }

    "unknown dotted OID text has no built-in ASN.1 encoding" {
        val attribute = AttributeTypeAndValue.fromString("1.2.3.4", "Test")

        attribute.oid shouldBe ObjectIdentifier("1.2.3.4")
        attribute.shouldBeInstanceOf<TextAttributeTypeAndValue>().text shouldBe "Test"
        attribute.sourceFormat shouldBe "<no source>"
        shouldThrow<Asn1Exception> { attribute.asn1.toRepresentation() }
            .cause.shouldBeInstanceOf<UnsupportedCryptoException>()
    }

    "Unsupported attribute strings report UnsupportedCryptoException" {
        shouldThrow<UnsupportedCryptoException> { AttributeTypeAndValue.fromString("UNKNOWN", "Test") }
        shouldThrow<UnsupportedCryptoException> { AttributeTypeAndValue.fromString("UNKNOWN=Test") }
        shouldThrow<UnsupportedCryptoException> { AttributeTypeAndValue.fromString("CN=#GG") }
    }
}
