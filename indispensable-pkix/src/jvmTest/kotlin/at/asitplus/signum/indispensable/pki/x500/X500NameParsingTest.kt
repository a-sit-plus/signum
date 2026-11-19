package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.signum.indispensable.pki.Name

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe

/**
 * Adapted from BouncyCastle's NameTest:
 * https://github.com/bcgit/bc-java/blob/main/core/src/test/java/org/bouncycastle/asn1/test/NameTest.java
 */
val NameParsingTest by matrixSuite {

    fun assertCanonical(input: String, expected: String) {
        Name.fromString(input).toRfc2253String() shouldBe expected
    }

    "testWhitespaces" {
        assertCanonical("CN=The     Legion", "CN=The Legion")
        assertCanonical("CN=   The Legion", "CN=The Legion")
        assertCanonical("CN=The Legion   ", "CN=The Legion")
        assertCanonical("CN=  the     legion ", "CN=the legion")
        assertCanonical("CN=  the     legion+C=AU, O=Legion ", "CN=the legion+C=AU,O=Legion")
    }

    "testEscaping" {
        assertCanonical("CN=a\\+b", "CN=a\\+b")
        assertCanonical("CN=a\\=b", "CN=a\\=b")
        assertCanonical("CN=\\#nothex#string", "CN=\\#nothex#string")
        // quoted/escaped '+' parses to the raw value and re-escapes on output (RFC 4514) — works for
        // PrintableString attributes (TELEPHONENUMBER) too, since the stored value is unescaped.
        assertCanonical("TELEPHONENUMBER=\"+61999999999\"", "TELEPHONENUMBER=\\+61999999999")
        assertCanonical("TELEPHONENUMBER=\\+61999999999", "TELEPHONENUMBER=\\+61999999999")
        assertCanonical("CN=\"a+b\"", "CN=a\\+b")
        assertCanonical("CN=\"a=b\"", "CN=a\\=b")
    }

    "testHexEncoded" {
        // 130138 is the DER encoding of PrintableString "8".
        assertCanonical("CN=#130138", "CN=8")
        // escaped '\#' is a literal '#', not a hexstring -> stays escaped
        assertCanonical("CN=\\#130138", "CN=\\#130138")
    }

    "testCompositeRDNs" {
        // RDNs with multiple attributes
        assertCanonical("SERIALNUMBER=16+CN=Steve Schoch", "CN=Steve Schoch+SERIALNUMBER=16")
        assertCanonical("CN=AA + SERIALNUMBER=BBB", "CN=AA+SERIALNUMBER=BBB")
    }

    "testLeadingTrailingSpaces" {
        // leading/trailing spaces must collapse or be escaped
        assertCanonical("CN=  Test Leading", "CN=Test Leading")
        assertCanonical("CN=Trailing  ", "CN=Trailing")
        assertCanonical("CN=  Multiple   Spaces  ", "CN=Multiple Spaces")
    }

    "testSpecialChars" {
        assertCanonical("CN=\\\"Quoted\\\"", "CN=\\\"Quoted\\\"")
        assertCanonical("CN=Plus\\+Equals\\=", "CN=Plus\\+Equals\\=")
        assertCanonical("CN=Backslash\\\\Test", "CN=Backslash\\\\Test")
    }

    "testEmptyValues" {
        assertCanonical("O=,CN=ABC,C=LT", "O=,CN=ABC,C=LT")
        assertCanonical("", "")
    }

    "testQuotedEqualityAndCase" {
        assertCanonical(
            "CN=\"  CA1 -   CP.04.03\", OU=Testing, O=U.S. Government, C=US",
            "CN=CA1 - CP.04.03,OU=Testing,O=U.S. Government,C=US"
        )
        assertCanonical(
            "CN=\"ca1 - CP.04.03  \", OU=Testing, O=U.S. Government, C=US",
            "CN=ca1 - CP.04.03,OU=Testing,O=U.S. Government,C=US"
        )
    }

    "testCanonicalAliasPreservesValueCase" {
        assertCanonical("CN=The Legion", "CN=The Legion")
        assertCanonical("cn=THE LEGION", "CN=THE LEGION")
    }

    "testTrailingBackslash" {
        assertCanonical("CN=trailing\\", "CN=trailing")
    }

    "testQuotedRDNCombination" {
        assertCanonical("CN=\"a+b\"+O=TestOrg", "CN=a\\+b+O=TestOrg")
        assertCanonical("CN=\"a=b\"+OU=\"Sub+Unit\"", "CN=a\\=b+OU=Sub\\+Unit")
    }

    "testUnknownOid" {
        assertCanonical("1.2.3.4.5=somevalue", "1.2.3.4.5=somevalue")
    }

    "testInvalidHexAfterHash" {
        shouldThrowAny { Name.fromString("CN=#nothex") }
        shouldThrowAny { Name.fromString("CN=#GG11") }
    }

}
