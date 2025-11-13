package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.cidre.IpAddress
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.nameConstraints_2_5_29_30
import at.asitplus.signum.indispensable.pki.generalNames.DNSName
import at.asitplus.signum.indispensable.pki.generalNames.GeneralName
import at.asitplus.signum.indispensable.pki.generalNames.GeneralNameOption
import at.asitplus.signum.indispensable.pki.generalNames.IPAddressName
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe


@OptIn(ExperimentalPkiApi::class)
val NameConstraintsExtensionsTest by testSuite {

    val testOid = KnownOIDs.nameConstraints_2_5_29_30
    val dummyValue = Asn1EncapsulatingOctetString(emptyList())

    fun dnsSubtree(name: String) = GeneralSubtree(
        base = GeneralName(
            DNSName(
                Asn1String.IA5(name),
                allowWildcard = false,
                type = GeneralNameOption.NameType.DNS
            )
        ),
        minimum = Asn1Integer(0)
    )

    fun ipSubtree(addr: String) = GeneralSubtree(
        base = GeneralName(IPAddressName(IpAddress(addr))),
        minimum = Asn1Integer(0)
    )

    "mergeWith should add excluded constraints when base has none" {
        val newExcluded = GeneralSubtrees(mutableListOf(dnsSubtree("bad.com")))
        val base = NameConstraintsExtension(testOid, false, dummyValue, permitted = null, excluded = null)
        val other = NameConstraintsExtension(testOid, false, dummyValue, permitted = null, excluded = newExcluded)

        base.mergeWith(other)

        base.excluded shouldNotBe null
        base.excluded!!.trees.size shouldBe 1
        base.excluded!!.trees.first().base.name.toString() shouldBe "bad.com"
    }

    "mergeWith should union excluded constraints when both have excluded" {
        val baseExcluded = GeneralSubtrees(mutableListOf(dnsSubtree("bad1.com")))
        val otherExcluded = GeneralSubtrees(mutableListOf(dnsSubtree("bad2.com")))
        val base = NameConstraintsExtension(testOid, false, dummyValue, excluded = baseExcluded)
        val other = NameConstraintsExtension(testOid, false, dummyValue, excluded = otherExcluded)

        base.mergeWith(other)

        base.excluded!!.trees.map { it.base.name.toString() }.sorted() shouldBe listOf("bad1.com", "bad2.com")
    }

    "mergeWith should add permitted when base has none" {
        val newPermitted = GeneralSubtrees(mutableListOf(dnsSubtree("example.com")))
        val base = NameConstraintsExtension(testOid, false, dummyValue, permitted = null)
        val other = NameConstraintsExtension(testOid, false, dummyValue, permitted = newPermitted)

        base.mergeWith(other)

        base.permitted shouldNotBe null
        base.permitted!!.trees.single().base.name.toString() shouldBe "example.com"
    }

    "mergeWith should merge permitted and produce exclusions when overlapping" {
        val basePermitted = GeneralSubtrees(mutableListOf(dnsSubtree("example.com")))
        val newPermitted = GeneralSubtrees(mutableListOf(dnsSubtree("sub.example.com")))
        val base = NameConstraintsExtension(testOid, false, dummyValue, permitted = basePermitted, excluded = null)
        val other = NameConstraintsExtension(testOid, false, dummyValue, permitted = newPermitted, excluded = null)

        base.mergeWith(other)

        // Should intersect, keeping the narrower one
        base.permitted!!.trees.single().base.name.toString() shouldBe "sub.example.com"
    }

    "mergeWith should keep IP and DNS separate when diff types" {
        val basePermitted = GeneralSubtrees(mutableListOf(ipSubtree("192.168.0.0")))
        val newPermitted = GeneralSubtrees(mutableListOf(dnsSubtree("example.com")))

        val base = NameConstraintsExtension(testOid, false, dummyValue, permitted = basePermitted)
        val other = NameConstraintsExtension(testOid, false, dummyValue, permitted = newPermitted)

        base.mergeWith(other)

        val names = base.permitted!!.trees.map { it.base.name.type }.toSet()
        names shouldBe setOf(GeneralNameOption.NameType.IP, GeneralNameOption.NameType.DNS)
    }

    "mergeWith should handle empty other" {
        val basePermitted = GeneralSubtrees(mutableListOf(dnsSubtree("example.com")))
        val base = NameConstraintsExtension(testOid, false, dummyValue, permitted = basePermitted)
        val other = NameConstraintsExtension(testOid, false, dummyValue)

        base.mergeWith(other)

        base.permitted!!.trees.single().base.name.toString() shouldBe "example.com"
        base.excluded shouldBe null
    }

    "mergeWith should handle null argument" {
        val base = NameConstraintsExtension(testOid, false, dummyValue)
        base.mergeWith(null)
        base.permitted shouldBe null
        base.excluded shouldBe null
    }
}