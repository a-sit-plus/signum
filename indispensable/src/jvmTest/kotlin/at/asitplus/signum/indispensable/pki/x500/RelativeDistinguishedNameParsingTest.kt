package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.encoding.parse
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlin.streams.asSequence

val RelativeDistinguishedNameParsingTest by matrixSuite {

    "Name should round-trip opaque attributes" { Name.fromString("1.2.3.4=#040101").toRfc2253String() shouldBe "1.2.3.4=#040101" }

    "Name should accept empty attribute values" {
        listOf("CN=", "CN=   ").forEach {
            Name.fromString(it).toRfc2253String() shouldBe "CN="
        }
    }

    "fromString should parse shorthand attributes in a multi-valued RDN" {
        val input = "CN=John+O=Company"
        val result = RelativeDistinguishedName.fromString(input)
        result.attrsAndValues shouldBe setOf(
            TextAttributeTypeAndValue(AttributeTypeAndValue.OID.commonName, "John"),
            TextAttributeTypeAndValue(AttributeTypeAndValue.OID.organizationName, "Company"),
        )
    }

    "fromString should keep quoted plus in the attribute value" {
        val input = """CN="John+Doe"+O=Company"""
        val result = RelativeDistinguishedName.fromString(input)
        result.attrsAndValues shouldBe setOf(
            TextAttributeTypeAndValue(AttributeTypeAndValue.OID.commonName, "John+Doe"),
            TextAttributeTypeAndValue(AttributeTypeAndValue.OID.organizationName, "Company"),
        )
    }

    "fromString should keep escaped plus in the attribute value" {
        val input = """CN=John\+Doe+O=Company"""
        val result = RelativeDistinguishedName.fromString(input)
        result.attrsAndValues shouldBe setOf(
            TextAttributeTypeAndValue(AttributeTypeAndValue.OID.commonName, "John+Doe"),
            TextAttributeTypeAndValue(AttributeTypeAndValue.OID.organizationName, "Company"),
        )
    }

    "fromString should split on the first equals sign" {
        val result = RelativeDistinguishedName.fromString("CN=John=Doe")
        result.attrsAndValues.single() shouldBe TextAttributeTypeAndValue(AttributeTypeAndValue.OID.commonName, "John=Doe")
    }

    "fromString should unescape equals in the attribute value" {
        val result = RelativeDistinguishedName.fromString("CN=John\\=Doe")
        result.attrsAndValues.single() shouldBe TextAttributeTypeAndValue(AttributeTypeAndValue.OID.commonName, "John=Doe")
    }

    "fromString should reject a missing equals sign" {
        shouldThrow<IllegalArgumentException> { RelativeDistinguishedName.fromString("CNJohnDoe") }
    }

    "fromString should parse valid RDN" {
        val rdnStr = "2.5.4.3=John Doe+2.5.4.10=Company"
        val rdn = RelativeDistinguishedName.fromString(rdnStr)
        rdn.attrsAndValues.size shouldBe 2
        // attrsAndValues is a Set; look up by displayName instead of positional index
        val cn =
            rdn.attrsAndValues.first { it.oid == ObjectIdentifier("2.5.4.3") } as AttributeTypeAndValue
        Asn1String.decodeFromTlv(cn.asn1.toRepresentation().value.asPrimitive()).value shouldBe "John Doe"
        val o =
            rdn.attrsAndValues.first { it.oid == ObjectIdentifier("2.5.4.10") } as AttributeTypeAndValue
        Asn1String.decodeFromTlv(o.asn1.toRepresentation().value.asPrimitive()).value shouldBe "Company"
    }

    "fromString should throw on invalid RDN" {
        val rdnStr = "CNJohn Doe+O=Company"
        shouldThrow<IllegalArgumentException> {
            RelativeDistinguishedName.fromString(rdnStr)
        }
    }

    "Name should respect quotes and convert between RFC and ASN.1 RDN order" {
        val name = Name.fromString("""2.5.4.3="Foo, Bar",2.5.4.10=Acme,2.5.4.6=DE""")

        name.relativeDistinguishedNames.map { it.attrsAndValues.single().oid } shouldBe listOf(
            ObjectIdentifier("2.5.4.6"),
            ObjectIdentifier("2.5.4.10"),
            ObjectIdentifier("2.5.4.3"),
        )
        name.toRfc2253String() shouldBe "CN=Foo\\, Bar,O=Acme,C=DE"
    }

    "Name should reject empty RDN segments" {
        listOf(
            ",2.5.4.3=Alice",
            "2.5.4.3=Alice,",
            "2.5.4.3=Alice,,2.5.4.10=Example",
            "2.5.4.3=Alice; ;2.5.4.10=Example",
        ).forEach { name ->
            shouldThrow<IllegalArgumentException> { Name.fromString(name) }
        }
    }

    "Name should accept the empty RDN sequence" {
        Name.fromString("").relativeDistinguishedNames shouldBe emptyList()
    }

    "decoded empty RDN should be invalid" {
        shouldThrow<Asn1Exception> { RelativeDistinguishedName.fromAsn1(X500RelativeDistinguishedName(emptySet())) }
    }

    "decoded RDN with a duplicate attribute OID should be invalid" {
        val oid = ObjectIdentifier("2.5.4.3")
        val rdn = X500RelativeDistinguishedName(
            setOf(
                X500AttributeTypeAndValue(oid, Asn1String.UTF8("Alice").encodeToTlv()),
                X500AttributeTypeAndValue(oid, Asn1String.UTF8("Bob").encodeToTlv()),
            )
        )

        shouldThrow<Asn1Exception> { RelativeDistinguishedName.fromAsn1(rdn) }
    }

    "parsed value accessor holds the raw, unescaped, case-preserved content" {
        // toRfc2253String would re-escape this; the stored value must not.
        val atv = AttributeTypeAndValue.fromString("2.5.4.3", """Foo\, Bar""")
                as AttributeTypeAndValue
        Asn1String.decodeFromTlv(atv.asn1.toRepresentation().value.asPrimitive()).value shouldBe "Foo, Bar"
    }

    "parsed value accessor strips surrounding quotes" {
        val rdn = RelativeDistinguishedName.fromString("""2.5.4.3="Foo+Bar"""")
        val cn = rdn.attrsAndValues.single() as AttributeTypeAndValue
        // '+' inside quotes is part of the value, not an ATV separator, and the quotes are dropped.
        Asn1String.decodeFromTlv(cn.asn1.toRepresentation().value.asPrimitive()).value shouldBe "Foo+Bar"
    }

    "hexstring form populates value with the exact DER element and preserves the string type" {
        // "#13025553" == PrintableString "US" (tag 0x13, len 2). toRfc2253String would obscure the tag.
        val atv = AttributeTypeAndValue.fromString("2.5.4.6", "#13025553")
                as AttributeTypeAndValue
        val decoded = Asn1String.decodeFromTlv(atv.asn1.toRepresentation().value.asPrimitive())
        decoded.value shouldBe "US"
        (decoded is Asn1String.Printable) shouldBe true
    }

    "ASN.1 accessor reflects the RDN's attributes" {
        val cn = X500AttributeTypeAndValue(ObjectIdentifier("2.5.4.3"), Asn1String.UTF8("Alice"))
        RelativeDistinguishedName(AttributeTypeAndValue.fromAsn1(cn)).asn1.toRepresentation() shouldBe X500RelativeDistinguishedName(setOf(cn))
    }

    "Core ATV decoding preserves malformed payloads without semantic RDN rejection" {
        (AttributeTypeAndValue.fromAsn1(
            X500AttributeTypeAndValue(
                ObjectIdentifier("2.5.4.3"),
                Asn1String.UTF8("Alice").encodeToTlv()
            )
        ) as TextAttributeTypeAndValue).text shouldBe "Alice"

        // IA5's permitted [\x00-\x7f] range
        val invalidIa5 = Asn1Element.parse(byteArrayOf(0x16, 0x01, 0x80.toByte()))
        val atv = AttributeTypeAndValue.fromAsn1(X500AttributeTypeAndValue(ObjectIdentifier("2.5.4.3"), invalidIa5))

        // raw value survives untouched and can still be received/decoded
        atv.asn1.toRepresentation().value shouldBe invalidIa5
        atv.asn1.toRepresentation().value.asPrimitive().content shouldBe byteArrayOf(0x80.toByte())
        Asn1String.decodeFromTlv(atv.asn1.toRepresentation().value.asPrimitive()).value.codePoints().asSequence().toList() shouldBe listOf(65533)

        val nonText = AttributeTypeAndValue.fromAsn1(
            X500AttributeTypeAndValue(
                ObjectIdentifier("2.5.4.3"),
                Asn1Integer(1).encodeToTlv()
            )
        )
        RelativeDistinguishedName(nonText).attrsAndValues.single() shouldBe nonText
    }

    "ATV equality should be symmetric across sourceRepresentation" {
        val oid = ObjectIdentifier("2.5.4.3")
        val generic =
            AttributeTypeAndValue.fromAsn1(X500AttributeTypeAndValue(oid, Asn1String.UTF8("Alice").encodeToTlv()))
        val x509 = AttributeTypeAndValue.fromAsn1(generic.asn1.toRepresentation())

        generic shouldBe x509
        x509 shouldBe generic
    }

    "GeneralName should retain the typed X.509 representation" {
        val dnsName = X509GeneralName.Dns("example.com")

        GeneralName.fromAsn1(dnsName).asn1.toRepresentation() shouldBe dnsName
    }

    /**
     * Adapted from BouncyCastle's X500NameTest:
     * https://github.com/bcgit/bc-java/blob/main/core/src/test/java/org/bouncycastle/asn1/test/X500NameTest.java
     */
    val bcExamples = listOf(
        "C=AU,ST=Victoria,L=South Melbourne,O=Connect 4 Pty Ltd,OU=Webserver Team,CN=www2.connect4.com.au,EMAILADDRESS=webmaster@connect4.com.au",
        "C=AU,ST=Victoria,L=South Melbourne,O=Connect 4 Pty Ltd,OU=Certificate Authority,CN=Connect 4 CA,EMAILADDRESS=webmaster@connect4.com.au",
        "C=AU,ST=QLD,CN=SSLeay/rsa test cert",
        "C=US,O=National Aeronautics and Space Administration,SERIALNUMBER=16+CN=Steve Schoch",
        "EMAILADDRESS=cooke@issl.atl.hp.com,C=US,OU=Hewlett Packard Company (ISSL),CN=Paul A. Cooke",
        """CN=*.canal-plus.com,OU=Provided by TBS INTERNET https://www.tbs-certificats.com/,OU=\ CANAL \+,O=CANAL\+DISTRIBUTION,L=issy les moulineaux,ST=Hauts de Seine,C=FR""",
        "O=Bouncy Castle,CN=www.bouncycastle.org\\ ",
        "O=Bouncy Castle,CN=c:\\\\fred\\\\bob",
        "C=DE,L=Berlin,O=Wohnungsbaugenossenschaft \\\"Humboldt-Universität\\\" eG,CN=transfer.wbg-hub.de"
    )

    bcExamples.forEachIndexed { index, dn ->
        "Bouncy Castle example #$index should round-trip through Name" {
            val name = Name.fromString(dn)
            Name.fromString(name.toRfc2253String()) shouldBe name
        }
    }

    val hexExamples = listOf(
        "\\20Test\\20X",
        "\\20Test\\20X\\20"
    )

    hexExamples.forEachIndexed { index, input ->
        "Hex escaping example #$index should round-trip through Name" {
            val dn = "CN=$input,O=\\ Test,C=GB"
            val name = Name.fromString(dn)
            name.relativeDistinguishedNames.size shouldBe 3
            Name.fromString(name.toRfc2253String()) shouldBe name
        }
    }
}
