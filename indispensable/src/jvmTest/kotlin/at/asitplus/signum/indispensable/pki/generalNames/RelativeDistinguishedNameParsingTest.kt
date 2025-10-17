package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName.Companion.splitFirstUnescaped
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName.Companion.splitRespectingEscapeAndQuotes
import at.asitplus.test.FreeSpec
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.comparables.shouldBeGreaterThan
import io.kotest.matchers.shouldBe

class RelativeDistinguishedNameParsingTest : FreeSpec({

    "splitRespectingEscapeAndQuotes should split simple RDN" {
        val input = "CN=John+O=Company"
        val result = splitRespectingEscapeAndQuotes(input, '+')
        result shouldBe listOf("CN=John", "O=Company")
    }

    "splitRespectingEscapeAndQuotes should ignore delimiter inside quotes" {
        val input = """CN="John+Doe"+O=Company"""
        val result = splitRespectingEscapeAndQuotes(input, '+')
        result shouldBe listOf("""CN="John+Doe"""", "O=Company")
    }

    "splitRespectingEscapeAndQuotes should preserve escaped delimiter" {
        val input = """CN=John\+Doe+O=Company"""
        val result = splitRespectingEscapeAndQuotes(input, '+')
        result shouldBe listOf("""CN=John\+Doe""", "O=Company")
    }

    "splitFirstUnescaped should split on first unescaped delimiter" {
        val input = "CN=John Doe"
        val result = splitFirstUnescaped(input, '=')
        result shouldBe listOf("CN", "John Doe")
    }

    "splitFirstUnescaped should preserve escaped delimiter" {
        val input = "CN=John\\=Doe"
        val result = splitFirstUnescaped(input, '=')
        result shouldBe listOf("CN", "John\\=Doe")
    }

    "splitFirstUnescaped should return whole string if delimiter missing" {
        val input = "CNJohnDoe"
        val result = splitFirstUnescaped(input, '=')
        result shouldBe listOf("CNJohnDoe")
    }

    "fromString should parse valid RDN" {
        val rdnStr = """CN=John Doe+O=Company"""
        val rdn = RelativeDistinguishedName.fromString(rdnStr)
        rdn.attrsAndValues.size shouldBe 2
        rdn.attrsAndValues[0].attrType shouldBe "CN"
        Asn1String.decodeFromTlv(rdn.attrsAndValues[0].value.asPrimitive()).value shouldBe "John Doe"
        rdn.attrsAndValues[1].attrType shouldBe "O"
        Asn1String.decodeFromTlv(rdn.attrsAndValues[1].value.asPrimitive()).value shouldBe "Company"
    }

    "fromString should throw on invalid RDN" {
        val rdnStr = "CNJohn Doe+O=Company"
        shouldThrow<IllegalArgumentException> {
            RelativeDistinguishedName.fromString(rdnStr)
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
            val rdnStrings = splitRespectingEscapeAndQuotes(dn, ',')

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
            val rdnStrings = splitRespectingEscapeAndQuotes(dn, ',')

            // 1. Ensure we split correctly
            rdnStrings.size shouldBe 3

            // 2. First RDN matches exactly
            rdnStrings[0] shouldBe "CN=$input"

            // 3. Check recombination matches original DN exactly
            val recombined = rdnStrings.joinToString(",")
            recombined shouldBe dn
        }
    }
})
