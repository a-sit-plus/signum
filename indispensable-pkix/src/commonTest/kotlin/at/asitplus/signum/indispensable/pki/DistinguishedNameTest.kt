package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1

import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue

import at.asitplus.signum.indispensable.pki.attributes.*

import at.asitplus.awesn1.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf

private data class TypedAttributeCase(
    val type: at.asitplus.awesn1.Identifiable,
    val names: Set<String>,
    val expected: (String) -> AttributeTypeAndValue,
)

private val typedAttributes = listOf(
    TypedAttributeCase(CommonName, setOf("CN", "COMMONNAME"), ::CommonName),
    TypedAttributeCase(Country, setOf("C", "COUNTRY", "COUNTRYNAME"), ::Country),
    TypedAttributeCase(Locality, setOf("L", "LOCALITY", "LOCALITYNAME"), ::Locality),
    TypedAttributeCase(StateOrProvince, setOf("ST", "S", "STATEORPROVINCENAME"), ::StateOrProvince),
    TypedAttributeCase(Street, setOf("STREET", "STREETADDRESS"), ::Street),
    TypedAttributeCase(Organization, setOf("O", "ORGANIZATION", "ORGANIZATIONNAME"), ::Organization),
    TypedAttributeCase(OrganizationalUnit, setOf("OU", "ORGANIZATIONALUNIT", "ORGANIZATIONALUNITNAME"), ::OrganizationalUnit),
    TypedAttributeCase(Title, setOf("T", "TITLE"), ::Title),
    TypedAttributeCase(TelephoneNumber, setOf("TELEPHONENUMBER"), ::TelephoneNumber),
    TypedAttributeCase(Surname, setOf("SURNAME"), ::Surname),
    TypedAttributeCase(SerialNumber, setOf("SERIALNUMBER"), ::SerialNumber),
    TypedAttributeCase(GivenName, setOf("GIVENNAME"), ::GivenName),
    TypedAttributeCase(Initials, setOf("INITIALS"), ::Initials),
    TypedAttributeCase(Generation, setOf("GENERATION"), ::Generation),
    TypedAttributeCase(DistinguishedNameQualifier, setOf("DNQUALIFIER", "DNQ"), ::DistinguishedNameQualifier),
    TypedAttributeCase(DomainComponent, setOf("DC"), ::DomainComponent),
    TypedAttributeCase(UserId, setOf("UID"), ::UserId),
    TypedAttributeCase(EmailAddress, setOf("EMAILADDRESS", "EMAIL"), ::EmailAddress),
)

val DistinguishedNameTest by matrixSuite {
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
                    val ot1 = AttributeTypeAndValue.fromAsn1(X500AttributeTypeAndValue(first, Asn1String.UTF8(firstUtf8)))
                    val ot2 = AttributeTypeAndValue.fromAsn1(X500AttributeTypeAndValue(first, Asn1String.UTF8(secondUtf8)))
                    val ot3 = AttributeTypeAndValue.fromAsn1(X500AttributeTypeAndValue(second, Asn1String.UTF8(firstUtf8)))
                    val ot4 = AttributeTypeAndValue.fromAsn1(X500AttributeTypeAndValue(second, Asn1String.UTF8(secondUtf8)))

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

        val decoded = (RelativeDistinguishedName.fromAsn1(rdn.asn1.toDer()))

        decoded shouldBe rdn
        decoded.attrsAndValues.size shouldBe 5
    }

    "RDN DER roundtrip with unknown attribute OID" {
        val source = X500AttributeTypeAndValue(ObjectIdentifier("1.2.3.4.5.6.7"), Asn1String.UTF8("custom"))
        val rdn = RelativeDistinguishedName(source)

        val encoded = rdn.asn1.toDer()
        val decoded = (RelativeDistinguishedName.fromAsn1(encoded))
        val attr = decoded.attrsAndValues.single()

        (attr is TextAttributeTypeAndValue) shouldBe false
        attr.oid shouldBe ObjectIdentifier("1.2.3.4.5.6.7")
        attr.asn1.toRepresentation() shouldBe source
        decoded.asn1.toDer() shouldBe encoded
    }

    "AttributeTypeAndValue ASN.1 decoder returns known subtype" {
        val attr = AttributeTypeAndValue.fromAsn1(
            X500AttributeTypeAndValue(CommonName.oid, Asn1String.UTF8("Jane Doe"))
        )

        attr::class shouldBe CommonName::class
    }

    "AttributeTypeAndValue string constructors use attribute syntax" {
        CommonName("Jane Doe").asn1.toRepresentation().value shouldBe Asn1String.UTF8("Jane Doe").encodeToTlv()
        Country("AT").asn1.toRepresentation().value shouldBe Asn1String.Printable("AT").encodeToTlv()
        DomainComponent("example").asn1.toRepresentation().value shouldBe Asn1String.IA5("example").encodeToTlv()
        DistinguishedNameQualifier("dnq").asn1.toRepresentation().value shouldBe Asn1String.Printable("dnq").encodeToTlv()
        EmailAddress("jane@example.test").asn1.toRepresentation().value shouldBe Asn1String.IA5("jane@example.test").encodeToTlv()
        SerialNumber("12345").asn1.toRepresentation().value shouldBe Asn1String.Printable("12345").encodeToTlv()
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

    "AttributeTypeAndValue providers parse aliases" {
        AttributeTypeAndValue.fromString("S", "Vienna") shouldBe StateOrProvince("Vienna")
        AttributeTypeAndValue.fromString("Title", "Dr") shouldBe Title("Dr")
        AttributeTypeAndValue.fromString("DNQ", "dnq") shouldBe DistinguishedNameQualifier("dnq")
        AttributeTypeAndValue.fromString("EMAIL", "jane@example.test") shouldBe
                EmailAddress("jane@example.test")
    }

    compact("PKIX providers replace construction but retain core aliases") - {
        data(typedAttributes, nameFn = { it.names.first() }) - { case ->
            data(case.names) test { name ->
                val parsed = AttributeTypeAndValue.fromString(name.lowercase(), "Test")

                val expected = case.expected("Test")
                parsed shouldBe expected
                parsed::class shouldBe expected::class
            }
        }
    }

    data(typedAttributes, nameFn = { "non-canonical ${it.names.first()}" }) test { case ->
        val canonical = case.expected("Test")
        val directoryString = Asn1String.decodeFromTlv(canonical.asn1.toRepresentation().value.asPrimitive()) is Asn1String.UTF8
        val wireString = if (directoryString) Asn1String.Printable("Test") else Asn1String.UTF8("Test")
        val source = X500AttributeTypeAndValue(case.type.oid, wireString)
        val original = RelativeDistinguishedName(source)
        val encoded = original.asn1.toDer()
        val decoded = RelativeDistinguishedName.fromAsn1(encoded)
        val attribute = decoded.attrsAndValues.single()

        if (directoryString) {
            attribute::class shouldBe canonical::class
            attribute.shouldBeInstanceOf<TextAttributeTypeAndValue>().text shouldBe "Test"
        } else {
            (attribute is TextAttributeTypeAndValue) shouldBe false
        }
        attribute.asn1.toRepresentation() shouldBe source
        decoded.asn1.toDer() shouldBe encoded
    }

    "Known attributes parsed by alias and dotted OID retain the DER string tag" {
        for (key in listOf("CN", CommonName.oid.toString())) {
            AttributeTypeAndValue.fromString(key, "Alice").shouldBeInstanceOf<CommonName>().text shouldBe "Alice"
            val attribute = AttributeTypeAndValue.fromString(key, "#130141").shouldBeInstanceOf<CommonName>()
            attribute.text shouldBe "A"
            attribute.asn1.toRepresentation().value shouldBe Asn1String.Printable("A").encodeToTlv()
        }
    }

    "AttributeTypeAndValue RFC2253 string escaping"  {
        CommonName((" Doe, John+Ops "))
            .toRfc2253String() shouldBe """CN=Doe\, John\+Ops"""
        CommonName(("#123"))
            .toRfc2253String() shouldBe """CN=\#123"""
        CommonName(("\\#not-hex"))
            .toRfc2253String() shouldBe """CN=\\#not-hex"""
    }
}
