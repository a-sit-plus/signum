package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.location
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.test.FreeSpec
import io.kotest.matchers.shouldBe

class GeneralNamesConstrainsTest : FreeSpec ({

    fun <T : GeneralNameOption> testGeneralNameConstraints(
        name: String,
        createInstance: (String) -> T,
        testName: String,
        testNameIsConstraint: Array<String>,
        testNameIsNotConstraint: Array<String>,
        widenNames: Array<String> = emptyArray(),
        narrowNames: Array<String> = emptyArray(),
        diffTypeOther: GeneralNameOption,
        matchName: String? = null
    ) {
        testNameIsConstraint.forEachIndexed { idx, constraint ->
            "$name MATCH/NARROWS [$idx]: $constraint vs $testName" {
                val base = createInstance(testName)
                val other = createInstance(constraint)
                val result = base.constrains(other)
                result shouldBe when (constraint) {
                    testName -> GeneralNameOption.ConstraintResult.MATCH
                    else -> GeneralNameOption.ConstraintResult.NARROWS
                }
            }
        }

        testNameIsNotConstraint.forEachIndexed { idx, constraint ->
            "$name SAME_TYPE [$idx]: $constraint vs $testName" {
                val base = createInstance(testName)
                val other = createInstance(constraint)
                base.constrains(other) shouldBe GeneralNameOption.ConstraintResult.SAME_TYPE
            }
        }

        "$name DIFF_TYPE when compared to other type" {
            val base = createInstance(testName)
            base.constrains(diffTypeOther) shouldBe GeneralNameOption.ConstraintResult.DIFF_TYPE
        }

        "$name MATCH when names are identical" {
            val base = createInstance(matchName ?: testName)
            base.constrains(createInstance(testName)) shouldBe GeneralNameOption.ConstraintResult.MATCH
        }

        widenNames.forEach { constraint ->
            "$constraint WIDENS $testName" {
                createInstance(constraint).constrains(createInstance(testName)) shouldBe
                        GeneralNameOption.ConstraintResult.WIDENS
            }
        }

        narrowNames.forEach { constraint ->
            "$testName NARROWS $constraint" {
                createInstance(testName).constrains(createInstance(constraint)) shouldBe
                        GeneralNameOption.ConstraintResult.NARROWS
            }
        }
    }

    fun rfc822(value: String) = RFC822Name(Asn1String.IA5(value))
    val testEmail = "test@abc.test.com"
    val testEmailIsConstraint = arrayOf("test@abc.test.com", "abc.test.com", ".test.com")
    val testEmailIsNotConstraint = arrayOf(".abc.test.com", "www.test.com", "test1@abc.test.com", "bc.test.com")
    val widenNames = arrayOf(".test.com")
    val narrowNames = arrayOf(".test.com")
    val dummyOtherDNS = DNSName(Asn1String.IA5(""), allowWildcard = true, performValidation = false)

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
        createInstance = ::x500NameFromString,
        testName = testDN,
        testNameIsConstraint = testDNIsConstraint,
        testNameIsNotConstraint = testDNIsNotConstraint,
        widenNames = widenDNs,
        narrowNames = narrowDNs,
        diffTypeOther = dummyOtherRFC
    )


    fun dns(value: String) = DNSName(Asn1String.IA5(value), allowWildcard = true, performValidation = false)

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

    UriName(Asn1String.IA5("https://[fe80::1%25eth0]/path"))
})


fun x500NameFromString(dn: String): X500Name {
    val rdnStrings = dn.split(",").map { it.trim() }
    val rdns = rdnStrings.map { rdnStr ->
        val (type, value) = rdnStr.split("=", limit = 2).map { it.trim() }
        val atv = when (type.uppercase()) {
            "CN" -> AttributeTypeAndValue.CommonName(Asn1String.UTF8(value))
            "O" -> AttributeTypeAndValue.Organization(Asn1String.UTF8(value))
            "OU" -> AttributeTypeAndValue.OrganizationalUnit(Asn1String.UTF8(value))
            "C" -> AttributeTypeAndValue.Country(Asn1String.UTF8(value))
            "EMAILADDRESS" -> AttributeTypeAndValue.EmailAddress(Asn1String.IA5(value))
            "L" -> AttributeTypeAndValue(KnownOIDs.location, Asn1String.UTF8(value).encodeToTlv())
            else -> throw IllegalArgumentException()
        }
        RelativeDistinguishedName(listOf(atv))
    }
    return X500Name(rdns)
}