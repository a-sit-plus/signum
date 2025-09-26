package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.test.FreeSpec
import io.kotest.matchers.shouldBe

class X500NameTest : FreeSpec ({

    fun assertCanonical(input: String, expected: String) {
        val name = X500Name.parse(input)
        val actual = name.toRfc2253String()
        actual shouldBe expected
    }

    "testWhitespaces" {
        assertCanonical("CN=The     Legion", "cn=the legion")
        assertCanonical("CN=   The Legion", "cn=the legion")
        assertCanonical("CN=The Legion   ", "cn=the legion")
        assertCanonical("CN=  the     legion ", "cn=the legion")
        assertCanonical("CN=  the     legion+C=AU, O=Legion ", "cn=the legion+c=au,o=legion")
    }

    "testEscaping" {
        assertCanonical("CN=a\\+b", "cn=a\\+b")
        assertCanonical("CN=a\\=b", "cn=a\\=b")
        assertCanonical("CN=\\#nothex#string", "cn=\\#nothex#string")
        assertCanonical("TELEPHONENUMBER=\"+61999999999\"", "telephonenumber=+61999999999")
        assertCanonical("TELEPHONENUMBER=\\+61999999999", "telephonenumber=\\+61999999999")
        assertCanonical("CN=\"a+b\"", "cn=a\\+b")
    }

    "testHexEncoded" {
        // hex-style ASN.1 values starting with #
        assertCanonical("CN=#130138", "cn=#130138")
        assertCanonical("CN=\\#130138", "cn=\\#130138")
    }

    "testCompositeRDNs" {
        // RDNs with multiple attributes
        assertCanonical("CN=a+b", "cn=a\\+b")
        assertCanonical("SERIALNUMBER=16+CN=Steve Schoch", "cn=steve schoch+serialnumber=16")
        assertCanonical("CN=AA + SERIALNUMBER=BBB", "cn=aa+serialnumber=bbb")
    }

    "testLeadingTrailingSpaces" {
        // leading/trailing spaces must collapse or be escaped
        assertCanonical("CN=  Test Leading", "cn=test leading")
        assertCanonical("CN=Trailing  ", "cn=trailing")
        assertCanonical("CN=  Multiple   Spaces  ", "cn=multiple spaces")
    }

    "testSpecialChars" {
        assertCanonical("CN=\\\"Quoted\\\"", "cn=\\\"quoted\\\"")
        assertCanonical("CN=Comma\\,Semi;Colon", "cn=comma\\,semi\\;colon")
        assertCanonical("CN=Plus\\+Equals\\=", "cn=plus\\+equals\\=")
        assertCanonical("CN=Backslash\\\\Test", "cn=backslash\\\\test")
    }
})