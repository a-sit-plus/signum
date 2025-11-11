package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.pki.generalNames.DNSName
import at.asitplus.signum.indispensable.pki.generalNames.GeneralName
import at.asitplus.signum.indispensable.pki.generalNames.GeneralNameOption
import at.asitplus.signum.indispensable.pki.generalNames.IPAddressName
import at.asitplus.signum.indispensable.pki.generalNames.RFC822Name
import at.asitplus.signum.indispensable.pki.generalNames.UriName
import at.asitplus.signum.indispensable.pki.generalNames.x500NameFromString
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import at.asitplus.testballoon.invoke

/**
 * Adapted from BouncyCastle's PKIXNameConstraintsTest:
 * https://github.com/bcgit/bc-java/blob/126ac9e14a0f56fae088973a777f1f90a521fd82/prov/src/test/java/org/bouncycastle/jce/provider/test/PKIXNameConstraintsTest.java
 */
@OptIn(ExperimentalPkiApi::class)
val GeneralSubtreesTest by testSuite {

    fun <T : GeneralNameOption> testSubtreeOperation(
        arr1: Array<String>,
        arr2: Array<String>,
        expected: Array<Array<String>>,
        createInstance: (String) -> T,
        operation: (GeneralSubtrees, GeneralSubtrees) -> Unit
    ) {
        require(arr1.size == arr2.size && arr1.size == expected.size) {
            "Arrays must have the same length"
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

            val expectedTrees = expected[i].map {
                GeneralSubtree(
                    base = GeneralName(createInstance(it)),
                    minimum = Asn1Integer(0)
                )
            }.toMutableList()

            operation(sub1, sub2)
            sub1.trees.sortedBy { it.base.name.toString() } shouldBe expectedTrees.sortedBy { it.base.name.toString() }
        }
    }

    fun <T : GeneralNameOption> testIntersectPairs(
        arr1: Array<String>,
        arr2: Array<String>,
        intersection: Array<String?>,
        createInstance: (String) -> T
    ) {
        val normalized = intersection.map { value ->
            if (value == null) emptyArray() else arrayOf(value)
        }.toTypedArray()

        testSubtreeOperation(arr1, arr2, normalized, createInstance) { a, b ->
            a.intersectAndReturnExclusions(b)
        }
    }

    fun <T : GeneralNameOption> testUnionPairs(
        arr1: Array<String>,
        arr2: Array<String>,
        union: Array<Array<String>>,
        createInstance: (String) -> T
    ) = testSubtreeOperation(arr1, arr2, union, createInstance) { a, b ->
        a.unionWith(b)
    }

    "test Rfc822Name" {
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

        val emailUnion = arrayOf(
            arrayOf("test@test.com", "test@test.abc.com"),
            arrayOf("test@test.com"),
            arrayOf("test@test.com", ".test.com"),
            arrayOf(".test.com"),
            arrayOf("test.com"),
            arrayOf("test@test.com", "test1.com"),
            arrayOf(".test.com", "test@test.com"),
            arrayOf(".test.com"),
            arrayOf(".test.com", ".test1.com"),
            arrayOf(".test.com", "test.com"),
            arrayOf("test.com"),
            arrayOf(".test.com"),
            arrayOf(".test.com", "abc.test1.com"),
            arrayOf("test1.com", "test.com"),
            arrayOf(".test.com", "test.com"),
            arrayOf(".test.com")
        )
        fun rfc822(value: String) = RFC822Name(Asn1String.IA5(value))

        testIntersectPairs(email1, email2, emailIntersect) { value: String -> rfc822(value) }
        testUnionPairs(email1, email2, emailUnion) { value: String -> rfc822(value) }
    }


    "test DnsName" {
        val dns1 = arrayOf("www.test.de", "www.test1.de", "www.test.de")
        val dns2 = arrayOf("test.de", "www.test.de", "www.test.de")
        val dnsIntersect = arrayOf( "www.test.de", null, "www.test.de" )
        val dnsUnion = arrayOf(arrayOf("test.de"), arrayOf("www.test1.de", "www.test.de"), arrayOf("www.test.de"))

        fun dns(value: String) = DNSName(
            Asn1String.IA5(value),
            allowWildcard = true,
            type = GeneralNameOption.NameType.DNS
        )

        testIntersectPairs(dns1, dns2, dnsIntersect, ::dns)
        testUnionPairs(dns1, dns2, dnsUnion, ::dns)
    }

    "test DNs" {
        val dn1 = arrayOf("O=test org, OU=test org unit, CN=John Doe")
        val dn2 = arrayOf("O=test org, OU=test org unit")
        val dnIntersection: Array<String?> = arrayOf("O=test org, OU=test org unit, CN=John Doe")
        val dnUnion = arrayOf(arrayOf("O=test org, OU=test org unit"))

        testIntersectPairs(dn1, dn2, dnIntersection, ::x500NameFromString)
        testUnionPairs(dn1, dn2, dnUnion, ::x500NameFromString)
    }

    "test URIName" {
        fun uri(value: String) = UriName(value)
        val uri1 = arrayOf("www.test.de", ".test.de", "test1.de", ".test.de")
        val uri2 = arrayOf("test.de", "www.test.de", "test1.de", ".test.de")
        val uriIntersection = arrayOf<String?>(null, "www.test.de", "test1.de", ".test.de")
        val uriUnion = arrayOf(arrayOf("www.test.de", "test.de"), arrayOf(".test.de"), arrayOf("test1.de"), arrayOf(".test.de"))

        testIntersectPairs(uri1, uri2, uriIntersection, ::uri)
        testUnionPairs(uri1, uri2, uriUnion, ::uri)
    }

    "test IPAddressName" {
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
        val ipUnion = arrayOf(
            arrayOf("192.168.0.1/22"),
            arrayOf("192.168.1.1/32"),
            arrayOf("192.168.0.1/24", "192.168.1.1/24")
        )

        fun ip(value: String) = IPAddressName.fromString(value)

        testIntersectPairs(ip1, ip2, ipIntersect, ::ip)
        testUnionPairs(ip1, ip2, ipUnion, ::ip)
    }
}