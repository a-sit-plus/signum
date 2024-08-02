package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue.*
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class DistinguishedNameTest : FreeSpec({
    "DistinguishedName test equals and hashCode" - {
        val oids = listOf(
            at.asitplus.signum.indispensable.asn1.KnownOIDs.countryName, at.asitplus.signum.indispensable.asn1.KnownOIDs.country, at.asitplus.signum.indispensable.asn1.KnownOIDs.houseIdentifier,
            at.asitplus.signum.indispensable.asn1.KnownOIDs.organizationName, at.asitplus.signum.indispensable.asn1.KnownOIDs.organization, at.asitplus.signum.indispensable.asn1.KnownOIDs.organizationalUnit,
            at.asitplus.signum.indispensable.asn1.KnownOIDs.organizationalPerson, at.asitplus.signum.indispensable.asn1.KnownOIDs.brainpoolP512r1
        )
        withData(oids) { first ->
            withData(oids) { second ->
                if (first != second) {
                    val cn1 = CommonName(first.encodeToTlv())
                    val cn2 = CommonName(first.encodeToTlv())
                    val cn3 = CommonName(second.encodeToTlv())
                    val c1 = Country(first.encodeToTlv())
                    val c2 = Country(second.encodeToTlv())
                    val o1 = Organization(first.encodeToTlv())
                    val o2 = Organization(second.encodeToTlv())
                    val ou1 = OrganizationalUnit(first.encodeToTlv())
                    val ou2 = OrganizationalUnit(second.encodeToTlv())
                    val ot1 = Other(first, first.encodeToTlv())
                    val ot2 = Other(first, second.encodeToTlv())
                    val ot3 = Other(second, first.encodeToTlv())
                    val ot4 = Other(second, second.encodeToTlv())

                    // equals()
                    cn1 shouldBe cn1
                    cn1 shouldBe cn2
                    c1 shouldBe c1
                    o1 shouldBe o1
                    ou1 shouldBe ou1
                    ot1 shouldBe ot1

                    cn1 shouldNotBe c1
                    cn1 shouldNotBe o1
                    cn1 shouldNotBe ou1
                    cn1 shouldNotBe ot1

                    cn1 shouldNotBe cn3
                    c1 shouldNotBe c2
                    o1 shouldNotBe o2
                    ou1 shouldNotBe ou2
                    ot1 shouldNotBe ot2
                    ot1 shouldNotBe ot3
                    ot1 shouldNotBe ot4

                    // hashCode()
                    cn1.hashCode() shouldBe cn1.hashCode()
                    cn1.hashCode() shouldBe cn2.hashCode()
                    c1.hashCode() shouldBe c1.hashCode()
                    o1.hashCode() shouldBe o1.hashCode()
                    ou1.hashCode() shouldBe ou1.hashCode()
                    ot1.hashCode() shouldBe ot1.hashCode()

                    cn1.hashCode() shouldNotBe c1.hashCode()
                    cn1.hashCode() shouldNotBe o1.hashCode()
                    cn1.hashCode() shouldNotBe ou1.hashCode()
                    cn1.hashCode() shouldNotBe ot1.hashCode()

                    cn1.hashCode() shouldNotBe cn3.hashCode()
                    c1.hashCode() shouldNotBe c2.hashCode()
                    o1.hashCode() shouldNotBe o2.hashCode()
                    ou1.hashCode() shouldNotBe ou2.hashCode()
                    ot1.hashCode() shouldNotBe ot2.hashCode()
                    ot1.hashCode() shouldNotBe ot3.hashCode()
                    ot1.hashCode() shouldNotBe ot4.hashCode()
                }
            }
        }
    }
})