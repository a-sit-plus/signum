package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.awesn1.encoding.parse
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.BaseAttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.BaseX509AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName.Companion.splitFirstUnescaped
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName.Companion.splitRespectingEscapeAndQuotes
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.comparables.shouldBeGreaterThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

private class NonX509AttributeTypeAndValue(oid: ObjectIdentifier) : BaseAttributeTypeAndValue(oid)

val RelativeDistinguishedNameParsingTest  by matrixSuite{

    "splitRespectingEscapeAndQuotes should split simple RDN" {
        val input = "CN=John+O=Company"
        val result = input.splitRespectingEscapeAndQuotes('+')
        result shouldBe listOf("CN=John", "O=Company")
    }

    "splitRespectingEscapeAndQuotes should ignore delimiter inside quotes" {
        val input = """CN="John+Doe"+O=Company"""
        val result = input.splitRespectingEscapeAndQuotes('+')
        result shouldBe listOf("""CN="John+Doe"""", "O=Company")
    }

    "splitRespectingEscapeAndQuotes should preserve escaped delimiter" {
        val input = """CN=John\+Doe+O=Company"""
        val result = input.splitRespectingEscapeAndQuotes('+')
        result shouldBe listOf("""CN=John\+Doe""", "O=Company")
    }

    "splitFirstUnescaped should split on first unescaped delimiter" {
        val input = "CN=John Doe"
        val result = input.splitFirstUnescaped('=')
        result shouldBe listOf("CN", "John Doe")
    }

    "splitFirstUnescaped should preserve escaped delimiter" {
        val input = "CN=John\\=Doe"
        val result = input.splitFirstUnescaped('=')
        result shouldBe listOf("CN", "John\\=Doe")
    }

    "splitFirstUnescaped should return whole string if delimiter missing" {
        val input = "CNJohnDoe"
        val result = input.splitFirstUnescaped('=')
        result shouldBe listOf("CNJohnDoe")
    }

    "fromString should parse valid RDN" {
        val rdnStr = "2.5.4.3=John Doe+2.5.4.10=Company"
        val rdn = RelativeDistinguishedName.fromString(rdnStr)
        rdn.attrsAndValues.size shouldBe 2
        // attrsAndValues is a Set; look up by displayName instead of positional index
        val cn = rdn.attrsAndValues.first { it.oid == ObjectIdentifier("2.5.4.3") } as AttributeTypeAndValue.X509Representable
        Asn1String.decodeFromTlv(cn.value.asPrimitive()).value shouldBe "John Doe"
        val o = rdn.attrsAndValues.first { it.oid == ObjectIdentifier("2.5.4.10") } as AttributeTypeAndValue.X509Representable
        Asn1String.decodeFromTlv(o.value.asPrimitive()).value shouldBe "Company"
    }

    "fromString should throw on invalid RDN" {
        val rdnStr = "CNJohn Doe+O=Company"
        shouldThrow<IllegalArgumentException> {
            RelativeDistinguishedName.fromString(rdnStr)
        }
    }

    "X500Name should respect quotes and convert between RFC and ASN.1 RDN order" {
        val name = X500Name.fromString("""2.5.4.3="Foo, Bar",2.5.4.10=Acme,2.5.4.6=DE""")

        name.relativeDistinguishedNames.map { it.attrsAndValues.single().oid } shouldBe listOf(
            ObjectIdentifier("2.5.4.6"),
            ObjectIdentifier("2.5.4.10"),
            ObjectIdentifier("2.5.4.3"),
        )
        name.toRfc2253String() shouldBe "2.5.4.3=foo\\, bar,2.5.4.10=acme,2.5.4.6=de"
    }

    "decoded empty RDN should be invalid" {
        RelativeDistinguishedName(X500RelativeDistinguishedName(emptySet())).isValid shouldBe false
    }

    "decoded RDN with a duplicate attribute OID should be invalid" {
        val oid = ObjectIdentifier("2.5.4.3")
        val rdn = X500RelativeDistinguishedName(
            setOf(
                X500AttributeTypeAndValue(oid, Asn1String.UTF8("Alice").encodeToTlv()),
                X500AttributeTypeAndValue(oid, Asn1String.UTF8("Bob").encodeToTlv()),
            )
        )

        RelativeDistinguishedName(rdn).isValid shouldBe false
    }

    "ATV equality should be symmetric across representations" {
        val oid = ObjectIdentifier("2.5.4.3")
        val generic = NonX509AttributeTypeAndValue(oid)
        val x509 = BaseX509AttributeTypeAndValue(oid, Asn1String.UTF8("Alice"))

        generic shouldNotBe x509
        x509 shouldNotBe generic
    }

    "GeneralName should reject a universal tag" {
        val universalDns = Asn1Element.parse(byteArrayOf(0x02, 0x01, 0x00))

        shouldThrow<Asn1Exception> {
            GeneralName.X509Representable.fromAsn1Representation(GeneralName.NameType.DNS, universalDns)
        }
    }

    "GeneralName should reject the wrong constructed bit" {
        val constructedDns = Asn1Element.parse(byteArrayOf(0xA2.toByte(), 0x00))

        shouldThrow<Asn1Exception> {
            GeneralName.X509Representable.fromAsn1Representation(GeneralName.NameType.DNS, constructedDns)
        }
    }

    "GeneralName should reject a tag that does not match its type" {
        val rfc822Name = Asn1Element.parse(byteArrayOf(0x81.toByte(), 0x00))

        shouldThrow<Asn1Exception> {
            GeneralName.X509Representable.fromAsn1Representation(GeneralName.NameType.DNS, rfc822Name)
        }
    }

    /**
     * Adapted from BouncyCastle's X500NameTest:
     * https://github.com/bcgit/bc-java/blob/main/core/src/test/java/org/bouncycastle/asn1/test/X500NameTest.java
     */
    val bcExamples = listOf(
        "C=AU,ST=Victoria,L=South Melbourne,O=Connect 4 Pty Ltd,OU=Webserver Team,CN=www2.connect4.com.au,E=webmaster@connect4.com.au",
        "C=AU,ST=Victoria,L=South Melbourne,O=Connect 4 Pty Ltd,OU=Certificate Authority,CN=Connect 4 CA,E=webmaster@connect4.com.au",
        "C=AU,ST=QLD,CN=SSLeay/rsa test cert",
        "C=US,O=National Aeronautics and Space Administration,SERIALNUMBER=16+CN=Steve Schoch",
        "E=cooke@issl.atl.hp.com,C=US,OU=Hewlett Packard Company (ISSL),CN=Paul A. Cooke",
        """CN=*.canal-plus.com,OU=Provided by TBS INTERNET https://www.tbs-certificats.com/,OU=\\ CANAL \\+,O=CANAL\\+DISTRIBUTION,L=issy les moulineaux,ST=Hauts de Seine,C=FR""",
        "O=Bouncy Castle,CN=www.bouncycastle.org\\ ",
        "O=Bouncy Castle,CN=c:\\\\fred\\\\bob",
        "C=DE,L=Berlin,O=Wohnungsbaugenossenschaft \\\"Humboldt-Universität\\\" eG,CN=transfer.wbg-hub.de"
    )

    bcExamples.forEachIndexed { index, dn ->
        "Bouncy Castle example #$index should round-trip through splitRespectingEscapeAndQuotes" {
            val rdnStrings = dn.splitRespectingEscapeAndQuotes(',')

            // Ensure we split into multiple RDNs if there are commas outside quotes
            rdnStrings.size shouldBeGreaterThan 0

            // Join back and normalize whitespace to roughly check round-trip
            val recombined = rdnStrings.joinToString(",") { it } // <- preserve trailing spaces and escapes
            recombined shouldBe dn
        }
    }


    val hexExamples = listOf(
        "\\20Test\\20X",
        "\\20Test\\20X\\20"
    )

    hexExamples.forEachIndexed { index, input ->
        "Hex escaping example #$index should preserve escapes" {
            val dn = "CN=$input,O=\\ Test,C=GB"
            val rdnStrings = dn.splitRespectingEscapeAndQuotes(',')

            // 1. Ensure we split correctly
            rdnStrings.size shouldBe 3

            // 2. First RDN matches exactly
            rdnStrings[0] shouldBe "CN=$input"

            // 3. Check recombination matches original DN exactly
            val recombined = rdnStrings.joinToString(",")
            recombined shouldBe dn
        }
    }
}
