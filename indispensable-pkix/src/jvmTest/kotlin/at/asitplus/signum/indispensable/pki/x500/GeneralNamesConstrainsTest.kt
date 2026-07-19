package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.location
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.SignumPkix
import at.asitplus.signum.indispensable.pki.attributes.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

/**
 * Adapted from BouncyCastle's PKIXNameConstraintsTest:
 * https://github.com/bcgit/bc-java/blob/126ac9e14a0f56fae088973a777f1f90a521fd82/prov/src/test/java/org/bouncycastle/jce/provider/test/PKIXNameConstraintsTest.java
 */
@OptIn(ExperimentalPkiApi::class)
val GeneralNamesConstrainsTest by matrixSuite {
    SignumPkix.install()

    fun <T : GeneralName> testGeneralNameConstraints(
        name: String,
        createInstance: (String) -> T,
        testName: String,
        testNameIsConstraint: Array<String>,
        testNameIsNotConstraint: Array<String>,
        widenNames: Array<String> = emptyArray(),
        narrowNames: Array<String> = emptyArray(),
        diffTypeOther: GeneralName,
        matchName: String? = null
    ) {
        testNameIsConstraint.forEachIndexed { idx, constraint ->
            "$name MATCH/NARROWS [$idx]: $constraint vs $testName" {
                val base = createInstance(testName)
                val other = createInstance(constraint)
                val result = base.constrains(other)
                result shouldBe when (constraint) {
                    testName -> GeneralName.ConstraintResult.MATCH
                    else -> GeneralName.ConstraintResult.NARROWS
                }
            }
        }

        testNameIsNotConstraint.forEachIndexed { idx, constraint ->
            "$name SAME_TYPE [$idx]: $constraint vs $testName" {
                val base = createInstance(testName)
                val other = createInstance(constraint)
                base.constrains(other) shouldBe GeneralName.ConstraintResult.SAME_TYPE
            }
        }

        "$name DIFF_TYPE when compared to other type" {
            val base = createInstance(testName)
            base.constrains(diffTypeOther) shouldBe GeneralName.ConstraintResult.DIFF_TYPE
        }

        "$name MATCH when names are identical" {
            val base = createInstance(matchName ?: testName)
            base.constrains(createInstance(testName)) shouldBe GeneralName.ConstraintResult.MATCH
        }

        widenNames.forEach { constraint ->
            "$constraint WIDENS $testName" {
                createInstance(constraint).constrains(createInstance(testName)) shouldBe
                        GeneralName.ConstraintResult.WIDENS
            }
        }

        narrowNames.forEach { constraint ->
            "$testName NARROWS $constraint" {
                createInstance(testName).constrains(createInstance(constraint)) shouldBe
                        GeneralName.ConstraintResult.NARROWS
            }
        }
    }

    fun rfc822(value: String) = RFC822Name(Asn1String.IA5(value))
    val testEmail = "test@abc.test.com"
    val testEmailIsConstraint = arrayOf("test@abc.test.com", "abc.test.com", ".test.com")
    val testEmailIsNotConstraint = arrayOf(".abc.test.com", "www.test.com", "test1@abc.test.com", "bc.test.com")
    val widenNames = arrayOf(".test.com")
    val narrowNames = arrayOf(".test.com")
    val dummyOtherDNS = DNSName(Asn1String.IA5("example.com"), allowWildcard = true)

    testGeneralNameConstraints(
        name = "RFC822Name.constrains",
        createInstance = ::rfc822,
        testName = testEmail,
        testNameIsConstraint = testEmailIsConstraint,
        testNameIsNotConstraint = testEmailIsNotConstraint,
        widenNames = widenNames,
        narrowNames = narrowNames,
        diffTypeOther = dummyOtherDNS
    )

    val testDN = "O=test org, OU=test org unit, CN=John Doe"
    val testDNIsConstraint = arrayOf(
        "O=test org, OU=test org unit",
        "O=test org, OU=test org unit, CN=John Doe"
    )
    val testDNIsNotConstraint = arrayOf(
        "O=test org, OU=test org unit, CN=John Doe2",
        "O=test org, OU=test org unit2",
        "O=test org, CN=John Doe"
    )
    val widenDNs = arrayOf(
        "O=test org, OU=test org unit"
    )
    val narrowDNs = arrayOf(
        "O=test org, OU=test org unit"
    )
    val dummyOtherRFC = RFC822Name(Asn1String.IA5("test@example.com"))

    testGeneralNameConstraints(
        name = "X500Name.constrains",
        createInstance = { DirectoryName(x500NameFromString(it)) },
        testName = testDN,
        testNameIsConstraint = testDNIsConstraint,
        testNameIsNotConstraint = testDNIsNotConstraint,
        widenNames = widenDNs,
        narrowNames = narrowDNs,
        diffTypeOther = dummyOtherRFC
    )


    fun dns(value: String) = DNSName(Asn1String.IA5(value), allowWildcard = true)

    val testDNS = "abc.test.com"
    val testDNSIsConstraint = arrayOf("test.com", "abc.test.com")
    val testDNSIsNotConstraint = arrayOf("wwww.test.com", "ww.test.com", "www.test.com")
    val widenDNSs = arrayOf("test.com")
    val narrowDNSs = arrayOf("test.com")

    testGeneralNameConstraints(
        name = "DNSName.constrains",
        createInstance = ::dns,
        testName = testDNS,
        testNameIsConstraint = testDNSIsConstraint,
        testNameIsNotConstraint = testDNSIsNotConstraint,
        widenNames = widenDNSs,
        narrowNames = narrowDNSs,
        diffTypeOther = dummyOtherRFC
    )

    fun uri(value: String) = UriName(value)
    val testURI = "http://karsten:password@abc.test.com:8080"
    val testURIIsConstraint = arrayOf(".com", ".test.com")
    val testURIIsNotConstraint = arrayOf("xyz.test.com", "bc.test.com")
    val widenURIs = arrayOf(".test.com")
    val narrowURIs = arrayOf(".test.com")
    val matchNameURi = "abc.test.com"

    testGeneralNameConstraints(
        name = "URIName.constrains",
        createInstance = ::uri,
        testName = testURI,
        testNameIsConstraint = testURIIsConstraint,
        testNameIsNotConstraint = testURIIsNotConstraint,
        widenNames = widenURIs,
        narrowNames = narrowURIs,
        diffTypeOther = dummyOtherRFC,
        matchNameURi
    )


    fun ip(value: String) = IPAddressName.fromString(value)
    val testIP = "192.168.1.2"
    val testIPIsConstraint = arrayOf(
        "192.168.1.1/24",
        "192.168.1.1/28"
    )
    val testIPIsNotConstraint = arrayOf(
        "192.168.3.1/30",
        "192.168.1.1"
    )
    val widenIps = arrayOf(
        "192.168.1.0/16"
    )
    val narrowIps = arrayOf(
        "192.168.1.0/16"
    )

    testGeneralNameConstraints(
        name = "IpAddressName.constrains",
        createInstance = ::ip,
        testName = testIP,
        testNameIsConstraint = testIPIsConstraint,
        testNameIsNotConstraint = testIPIsNotConstraint,
        widenNames = widenIps,
        narrowNames = narrowIps,
        diffTypeOther = dummyOtherRFC,
    )

    testGeneralNameConstraints(
        name = "IpAddressName.constrains",
        createInstance = ::ip,
        testName = testIP,
        testNameIsConstraint = testIPIsConstraint,
        testNameIsNotConstraint = testIPIsNotConstraint,
        widenNames = widenIps,
        narrowNames = narrowIps,
        diffTypeOther = IPAddressName.fromString("2001:db8::8a2e:370:7334"),
    )
}


fun x500NameFromString(dn: String): X500Name {
    val rdnStrings = dn.split(",").map { it.trim() }
    val rdns = rdnStrings.map { rdnStr ->
        val (type, value) = rdnStr.split("=", limit = 2).map { it.trim() }
        val atv = when (type.uppercase()) {
            "CN" -> CommonName(value)
            "O" -> Organization(value)
            "OU" -> OrganizationalUnit(value)
            "C" -> Country(value)
            "EMAILADDRESS" -> EmailAddress(value)
            "L" -> AttributeTypeAndValue(KnownOIDs.location, Asn1String.UTF8(value).encodeToTlv())
            else -> throw IllegalArgumentException()
        }
        RelativeDistinguishedName(atv)
    }
    return X500Name(rdns)
}