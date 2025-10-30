package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe

/**
 * Adapted from BouncyCastle's X500NameTest:
 * https://github.com/bcgit/bc-java/blob/main/core/src/test/java/org/bouncycastle/asn1/test/X500NameTest.java
 */
val X500NameParsingTest by testSuite {

    fun assertCanonical(input: String, expected: String) {
        val name = X500Name.fromString(input)
        val actual = name.toRfc2253String()
        println(actual)
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
        assertCanonical("CN=\"a+b\"", "cn=a+b")
        assertCanonical("CN=\"a=b\"", "cn=a=b")
    }

    "testHexEncoded" {
        // hex-style ASN.1 values starting with #
        assertCanonical("CN=#130138", "cn=#130138")
        assertCanonical("CN=\\#130138", "cn=\\#130138")
    }

    "testCompositeRDNs" {
        // RDNs with multiple attributes
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
        assertCanonical("CN=Plus\\+Equals\\=", "cn=plus\\+equals\\=")
        assertCanonical("CN=Backslash\\\\Test", "cn=backslash\\\\test")
    }

    "testEmptyValues" {
        assertCanonical("O=,CN=ABC,C=LT", "o=,cn=abc,c=lt")
        assertCanonical("", "")
    }

    "testQuotedEqualityAndCase" {
        assertCanonical(
            "CN=\"  CA1 -   CP.04.03\", OU=Testing, O=U.S. Government, C=US",
            "cn=ca1 - cp.04.03,ou=testing,o=u.s. government,c=us"
        )
        assertCanonical(
            "CN=\"ca1 - CP.04.03  \", OU=Testing, O=U.S. Government, C=US",
            "cn=ca1 - cp.04.03,ou=testing,o=u.s. government,c=us"
        )
    }

    "testCaseInsensitiveEquality" {
        assertCanonical("CN=The Legion", "cn=the legion")
        assertCanonical("cn=THE LEGION", "cn=the legion")
    }

    "testTrailingBackslash" {
        assertCanonical("CN=trailing\\", "cn=trailing")
    }

    "testQuotedRDNCombination" {
        assertCanonical("CN=\"a+b\"+O=TestOrg", "cn=a+b+o=testorg")
        assertCanonical("CN=\"a=b\"+OU=\"Sub+Unit\"", "cn=a=b+ou=sub+unit")
    }

    "testUnknownOid" {
        assertCanonical("1.2.3.4.5=somevalue", "1.2.3.4.5=somevalue")
    }

    "testInvalidHexAfterHash" {
        assertCanonical("CN=#nothex", "cn=\\#nothex")
        assertCanonical("CN=#GG11", "cn=\\#gg11")
    }

}