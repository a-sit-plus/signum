package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.signum.indispensable.decodeFromDer
import at.asitplus.signum.indispensable.encodeToDer
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

private class RegisteredTestAttribute : BaseX509AttributeTypeAndValue {
    constructor(value: String) : super(Companion.oid, Asn1String.UTF8(value))
    internal constructor(src: X500AttributeTypeAndValue) : super(src)

    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("1.2.3.4.5.6.8")
        override val canonicalName = "TESTATTR"
        override val aliases = setOf("TA")

        init { register() }

        override fun fromString(value: String) = RegisteredTestAttribute(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = RegisteredTestAttribute(src)
    }
}

private class FirstOverrideRegisteredTestAttribute : BaseX509AttributeTypeAndValue {
    constructor(value: String) : super(Companion.oid, Asn1String.UTF8(value))
    internal constructor(src: X500AttributeTypeAndValue) : super(src)

    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = ObjectIdentifier("1.2.3.4.5.6.9")
        override val canonicalName = "OVERRIDEATTR"
        override val aliases = emptySet<String>()

        override fun fromString(value: String) = FirstOverrideRegisteredTestAttribute(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = FirstOverrideRegisteredTestAttribute(src)
    }
}

private class SecondOverrideRegisteredTestAttribute : BaseX509AttributeTypeAndValue {
    constructor(value: String) : super(Companion.oid, Asn1String.UTF8(value))
    internal constructor(src: X500AttributeTypeAndValue) : super(src)

    companion object : AttributeTypeAndValue.Descriptor {
        override val oid = FirstOverrideRegisteredTestAttribute.oid
        override val canonicalName = "OVERRIDEATTR"
        override val aliases = emptySet<String>()

        override fun fromString(value: String) = SecondOverrideRegisteredTestAttribute(value)
        override fun fromAsn1Representation(src: X500AttributeTypeAndValue) = SecondOverrideRegisteredTestAttribute(src)
    }
}

val DistinguishedNameTest by testSuite {
    "DistinguishedName test equals and hashCode" - {
        val oids = listOf(
            KnownOIDs.countryName, KnownOIDs.country, KnownOIDs.houseIdentifier,
            KnownOIDs.organizationName, KnownOIDs.organization, KnownOIDs.organizationalUnit,
            KnownOIDs.organizationalPerson, KnownOIDs.brainpoolP512r1
        )
        withData(oids) - { first ->
            withData(oids, compact= true) { second ->
                if (first != second) {
                    val firstString = first.toString()
                    val secondString = second.toString()
                    val firstUtf8 = (firstString)
                    val secondUtf8 =(secondString)
                    val cn1 = AttributeTypeAndValue.CommonName(firstUtf8)
                    val cn2 = AttributeTypeAndValue.CommonName(firstUtf8)
                    val cn3 = AttributeTypeAndValue.CommonName(secondUtf8)
                    val c1 = AttributeTypeAndValue.Country(firstString)
                    val c2 = AttributeTypeAndValue.Country(secondString)
                    val o1 = AttributeTypeAndValue.Organization(firstUtf8)
                    val o2 = AttributeTypeAndValue.Organization(secondUtf8)
                    val ou1 = AttributeTypeAndValue.OrganizationalUnit(firstUtf8)
                    val ou2 = AttributeTypeAndValue.OrganizationalUnit(secondUtf8)
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
                AttributeTypeAndValue.CommonName(("Jane Doe")),
                AttributeTypeAndValue.Country("AT"),
                AttributeTypeAndValue.Organization(("A-SIT")),
                AttributeTypeAndValue.OrganizationalUnit(("Crypto")),
                AttributeTypeAndValue.UserId(("jdoe")),
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
            AttributeTypeAndValue.CommonName.oid,
            Asn1String.UTF8("Jane Doe").encodeToTlv(),
        )

        attr::class shouldBe AttributeTypeAndValue.CommonName::class
    }

    "AttributeTypeAndValue string constructors use attribute syntax" {
        AttributeTypeAndValue.CommonName("Jane Doe").value shouldBe Asn1String.UTF8("Jane Doe").encodeToTlv()
        AttributeTypeAndValue.Country("AT").value shouldBe Asn1String.Printable("AT").encodeToTlv()
        AttributeTypeAndValue.DomainComponent("example").value shouldBe Asn1String.IA5("example").encodeToTlv()
        AttributeTypeAndValue.DistinguishedNameQualifier("dnq").value shouldBe Asn1String.Printable("dnq").encodeToTlv()
        AttributeTypeAndValue.EmailAddress("jane@example.test").value shouldBe Asn1String.IA5("jane@example.test").encodeToTlv()
        AttributeTypeAndValue.SerialNumber("12345").value shouldBe Asn1String.Printable("12345").encodeToTlv()
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
                    AttributeTypeAndValue.CommonName("Jane"),
                    AttributeTypeAndValue.CommonName("John"),
                )
            )
        }
    }

    "RDN from string" {
        val rdn = RelativeDistinguishedName.fromString("CN=John+O=Org")

        rdn.attrsAndValues shouldBe setOf(
            AttributeTypeAndValue.CommonName("John"),
            AttributeTypeAndValue.Organization("Org"),
        )
    }

    "AttributeTypeAndValue registry parses aliases" {
        AttributeTypeAndValue.fromString("S", "Vienna") shouldBe AttributeTypeAndValue.StateOrProvince("Vienna")
        AttributeTypeAndValue.fromString("DNQ", "dnq") shouldBe AttributeTypeAndValue.DistinguishedNameQualifier("dnq")
        AttributeTypeAndValue.fromString("EMAIL", "jane@example.test") shouldBe
                AttributeTypeAndValue.EmailAddress("jane@example.test")
    }

    "AttributeTypeAndValue custom registry parses custom subtype" {
        RegisteredTestAttribute
        val value = Asn1String.UTF8("custom").encodeToTlv()

        AttributeTypeAndValue.fromString("TESTATTR", "custom")!!::class shouldBe RegisteredTestAttribute::class
        AttributeTypeAndValue.fromString("TA", "custom")!!::class shouldBe RegisteredTestAttribute::class
        AttributeTypeAndValue(RegisteredTestAttribute.oid, value)::class shouldBe RegisteredTestAttribute::class

        val rdn = RelativeDistinguishedName(AttributeTypeAndValue(RegisteredTestAttribute.oid, value))
        val decoded = RelativeDistinguishedName.decodeFromDer(rdn.encodeToDer())

        decoded.attrsAndValues.single()::class shouldBe RegisteredTestAttribute::class
    }

    "AttributeTypeAndValue registry uses last registration" {
        AttributeTypeAndValue.Registry.register(FirstOverrideRegisteredTestAttribute)
        AttributeTypeAndValue.Registry.register(SecondOverrideRegisteredTestAttribute)

        AttributeTypeAndValue.fromString("OVERRIDEATTR", "custom")!!::class shouldBe SecondOverrideRegisteredTestAttribute::class
        AttributeTypeAndValue(
            FirstOverrideRegisteredTestAttribute.oid,
            Asn1String.UTF8("custom").encodeToTlv(),
        )::class shouldBe SecondOverrideRegisteredTestAttribute::class
    }

    "AttributeTypeAndValue RFC2253 string escaping"  {
        AttributeTypeAndValue.CommonName((" Doe, John+Ops "))
            .toRfc2253String() shouldBe """cn=\ Doe\, John\+Ops\ """
        AttributeTypeAndValue.CommonName(("#123"))
            .toRfc2253String() shouldBe """cn=\#123"""
        AttributeTypeAndValue.CommonName(("\\#not-hex"))
            .toRfc2253String() shouldBe """cn=\#not-hex"""
    }
}
