package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.pki.attributes.*
import at.asitplus.signum.indispensable.pki.SignumPkix

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.signum.indispensable.decodeFromDer
import at.asitplus.signum.indispensable.encodeToDer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val DistinguishedNameTest by matrixSuite {
    SignumPkix.install()
    compact("DistinguishedName test equals and hashCode") - {
        val oids = listOf(
            KnownOIDs.countryName, KnownOIDs.country, KnownOIDs.houseIdentifier,
            KnownOIDs.organizationName, KnownOIDs.organization, KnownOIDs.organizationalUnit,
            KnownOIDs.organizationalPerson, KnownOIDs.brainpoolP512r1
        )
        data(oids) - { first ->
            data(oids) test { second ->
                if (first != second) {
                    val firstString = first.toString()
                    val secondString = second.toString()
                    val firstUtf8 = (firstString)
                    val secondUtf8 =(secondString)
                    val cn1 = CommonName(firstUtf8)
                    val cn2 = CommonName(firstUtf8)
                    val cn3 = CommonName(secondUtf8)
                    val c1 = Country(firstString)
                    val c2 = Country(secondString)
                    val o1 = Organization(firstUtf8)
                    val o2 = Organization(secondUtf8)
                    val ou1 = OrganizationalUnit(firstUtf8)
                    val ou2 = OrganizationalUnit(secondUtf8)
                    val ot1 = BaseX509AttributeTypeAndValue(first, Asn1String.UTF8(firstUtf8))
                    val ot2 = BaseX509AttributeTypeAndValue(first, Asn1String.UTF8(secondUtf8))
                    val ot3 = BaseX509AttributeTypeAndValue(second,Asn1String.UTF8( firstUtf8))
                    val ot4 = BaseX509AttributeTypeAndValue(second, Asn1String.UTF8(secondUtf8))

                    // equals()
                    cn1 shouldBe cn1
                    cn1 shouldBe cn2
                    c1 shouldBe c1
                    o1 shouldBe o1
                    ou1 shouldBe ou1
                    ot1 shouldBe ot1

                    cn1 shouldNotBe c1
                    cn1 shouldNotBe o1
                    cn1 shouldNotBe ou1
                    cn1 shouldNotBe ot1

                    cn1 shouldNotBe cn3
                    c1 shouldNotBe c2
                    o1 shouldNotBe o2
                    ou1 shouldNotBe ou2
                    ot1 shouldNotBe ot2
                    ot1 shouldNotBe ot3
                    ot1 shouldNotBe ot4

                    // hashCode()
                    cn1.hashCode() shouldBe cn1.hashCode()
                    cn1.hashCode() shouldBe cn2.hashCode()
                    c1.hashCode() shouldBe c1.hashCode()
                    o1.hashCode() shouldBe o1.hashCode()
                    ou1.hashCode() shouldBe ou1.hashCode()
                    ot1.hashCode() shouldBe ot1.hashCode()

                    cn1.hashCode() shouldNotBe c1.hashCode()
                    cn1.hashCode() shouldNotBe o1.hashCode()
                    cn1.hashCode() shouldNotBe ou1.hashCode()
                    cn1.hashCode() shouldNotBe ot1.hashCode()

                    cn1.hashCode() shouldNotBe cn3.hashCode()
                    c1.hashCode() shouldNotBe c2.hashCode()
                    o1.hashCode() shouldNotBe o2.hashCode()
                    ou1.hashCode() shouldNotBe ou2.hashCode()
                    ot1.hashCode() shouldNotBe ot2.hashCode()
                    ot1.hashCode() shouldNotBe ot3.hashCode()
                    ot1.hashCode() shouldNotBe ot4.hashCode()
                }
            }
        }
    }

    "RDN DER roundtrip" {
        val rdn = RelativeDistinguishedName(
            setOf(
                CommonName(("Jane Doe")),
                Country("AT"),
                Organization(("A-SIT")),
                OrganizationalUnit(("Crypto")),
                UserId(("jdoe")),
            )
        )

        val decoded = RelativeDistinguishedName.decodeFromDer(rdn.encodeToDer())

        decoded shouldBe rdn
        decoded.attrsAndValues.size shouldBe 5
    }

    "RDN DER roundtrip with unknown attribute OID" {
        val rdn = RelativeDistinguishedName(
            AttributeTypeAndValue(
                ObjectIdentifier("1.2.3.4.5.6.7"),
                Asn1String.UTF8("custom").encodeToTlv(),
            )
        )

        val encoded = rdn.encodeToDer()
        val decoded = RelativeDistinguishedName.decodeFromDer(encoded)
        val attr = decoded.attrsAndValues.single()

        attr::class shouldBe BaseX509AttributeTypeAndValue::class
        attr.oid shouldBe ObjectIdentifier("1.2.3.4.5.6.7")
        (attr is AttributeTypeAndValue.X509Representable) shouldBe true
        decoded.encodeToDer() shouldBe encoded
    }

    "AttributeTypeAndValue oid factory returns known subtype" {
        val attr = AttributeTypeAndValue(
            CommonName.oid,
            Asn1String.UTF8("Jane Doe").encodeToTlv(),
        )

        attr::class shouldBe CommonName::class
    }

    "AttributeTypeAndValue string constructors use attribute syntax" {
        CommonName("Jane Doe").value shouldBe Asn1String.UTF8("Jane Doe").encodeToTlv()
        Country("AT").value shouldBe Asn1String.Printable("AT").encodeToTlv()
        DomainComponent("example").value shouldBe Asn1String.IA5("example").encodeToTlv()
        DistinguishedNameQualifier("dnq").value shouldBe Asn1String.Printable("dnq").encodeToTlv()
        EmailAddress("jane@example.test").value shouldBe Asn1String.IA5("jane@example.test").encodeToTlv()
        SerialNumber("12345").value shouldBe Asn1String.Printable("12345").encodeToTlv()
    }

    "RDN manual construction rejects empty set" {
        shouldThrow<Asn1Exception> {
            RelativeDistinguishedName(emptySet())
        }
    }

    "RDN manual construction rejects duplicate attribute OID" {
        shouldThrow<Asn1Exception> {
            RelativeDistinguishedName(
                setOf(
                    CommonName("Jane"),
                    CommonName("John"),
                )
            )
        }
    }

    "RDN from string" {
        val rdn = RelativeDistinguishedName.fromString("CN=John+O=Org")

        rdn.attrsAndValues shouldBe setOf(
            CommonName("John"),
            Organization("Org"),
        )
    }

    "AttributeTypeAndValue registry parses aliases" {
        AttributeTypeAndValue.fromString("S", "Vienna") shouldBe StateOrProvince("Vienna")
        AttributeTypeAndValue.fromString("DNQ", "dnq") shouldBe DistinguishedNameQualifier("dnq")
        AttributeTypeAndValue.fromString("EMAIL", "jane@example.test") shouldBe
                EmailAddress("jane@example.test")
    }

    "AttributeTypeAndValue RFC2253 string escaping"  {
        CommonName((" Doe, John+Ops "))
            .toRfc2253String() shouldBe """cn=doe\, john\+ops""" // RFC 4514: trimmed, lower-cased, specials escaped
        CommonName(("#123"))
            .toRfc2253String() shouldBe """cn=\#123"""
        CommonName(("\\#not-hex"))
            .toRfc2253String() shouldBe """cn=\\#not-hex""" // raw value contains a literal backslash -> escaped
    }
}
