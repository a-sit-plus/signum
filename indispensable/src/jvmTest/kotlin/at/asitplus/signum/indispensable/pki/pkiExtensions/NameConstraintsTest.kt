package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.pki.generalNames.DNSName
import at.asitplus.signum.indispensable.pki.generalNames.GeneralName
import at.asitplus.signum.indispensable.pki.generalNames.GeneralNameOption
import at.asitplus.signum.indispensable.pki.generalNames.IPAddressName
import at.asitplus.signum.indispensable.pki.generalNames.RFC822Name
import at.asitplus.signum.indispensable.pki.generalNames.UriName
import at.asitplus.signum.indispensable.pki.generalNames.x500NameFromString
import at.asitplus.test.FreeSpec
import io.kotest.matchers.shouldBe

class NameConstraintsTest : FreeSpec ({

    fun <T : GeneralNameOption> testIntersectPairs(arr1: Array<String>, arr2: Array<String>, intersection: Array<String?>, createInstance: (String) -> T) {
        if (arr1.size != arr2.size) {
            throw IllegalArgumentException("Arrays must have the same length")
        }

        for (i in arr1.indices) {
            val sub1 = GeneralSubtrees(
                trees = mutableListOf(
                    GeneralSubtree(
                        base = GeneralName(createInstance(arr1[i])),
                        minimum = Asn1Integer(0)
                    )
                )
            )

            val sub2 = GeneralSubtrees(
                trees = mutableListOf(
                    GeneralSubtree(
                        base = GeneralName(createInstance(arr2[i])),
                        minimum = Asn1Integer(0)
                    )
                )
            )

            val intersec = intersection[i]?.let {
                    mutableListOf(
                        GeneralSubtree(
                            base = GeneralName(createInstance(it)),
                            minimum = Asn1Integer(0)
                        )
                    )
                } ?: mutableListOf()

            sub1.intersectAndReturnExclusions(sub2)
            sub1.trees shouldBe intersec
        }
    }

    val email1 = arrayOf(
        "test@test.com",
        "test@test.com",
        "test@test.com",
        "test@abc.test.com",
        "test@test.com",
        "test@test.com",
        ".test.com",
        ".test.com",
        ".test.com",
        ".test.com",
        "test.com",
        "abc.test.com",
        "abc.test1.com",
        "test.com",
        "test.com",
        ".test.com"
    )

    val email2 = arrayOf(
        "test@test.abc.com",
        "test@test.com",
        ".test.com",
        ".test.com",
        "test.com",
        "test1.com",
        "test@test.com",
        ".test.com",
        ".test1.com",
        "test.com",
        "test.com",
        ".test.com",
        ".test.com",
        "test1.com",
        ".test.com",
        "abc.test.com"
    )

    val emailIntersect: Array<String?> = arrayOf(
        null, "test@test.com", null, "test@abc.test.com", "test@test.com", null,
        null, ".test.com", null, null, "test.com", "abc.test.com", null,
        null, null, "abc.test.com"
    )
    fun rfc822(value: String) = RFC822Name(Asn1String.IA5(value))
    "testRfc" {
        testIntersectPairs(email1, email2, emailIntersect, ::rfc822)
    }

    val dns1 = arrayOf("www.test.de", "www.test1.de", "www.test.de")
    val dns2 = arrayOf("test.de", "www.test.de", "www.test.de")
    val dnsIntersect = arrayOf( "www.test.de", null, "www.test.de" )
    fun dns(value: String) = DNSName(Asn1String.IA5(value), allowWildcard = true, performValidation = false)

    "testDns" {
        testIntersectPairs(dns1, dns2, dnsIntersect, ::dns)
    }

    val dn1 = arrayOf("O=test org, OU=test org unit, CN=John Doe")
    val dn2 = arrayOf("O=test org, OU=test org unit")
    val dnIntersection: Array<String?> = arrayOf("O=test org, OU=test org unit, CN=John Doe")

    "testDNs" {
        testIntersectPairs(dn1, dn2, dnIntersection, ::x500NameFromString)
    }

    fun uri(value: String) = UriName(value)
    val uri1 = arrayOf("www.test.de", ".test.de", "test1.de", ".test.de")
    val uri2 = arrayOf("test.de", "www.test.de", "test1.de", ".test.de")
    val uriIntersection = arrayOf<String?>(null, "www.test.de", "test1.de", ".test.de")

    "testURI" {
        testIntersectPairs(uri1, uri2, uriIntersection, ::uri)
    }

    val ip1 = arrayOf(
        "192.168.1.1/23",
        "192.168.1.1/32",
        "192.168.1.1/24"
    )
    val ip2 = arrayOf(
        "192.168.0.1/22",
        "192.168.1.1/32",
        "192.168.0.1/24"
    )
    val ipIntersect = arrayOf(
        "192.168.1.1/23",
        "192.168.1.1/32",
        null
    )

    fun ip(value: String) = IPAddressName.fromString(value)

    "testIP" {
        testIntersectPairs(ip1, ip2, ipIntersect, ::ip)
    }

})