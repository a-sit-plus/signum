package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.brainpoolP512r1
import at.asitplus.awesn1.country
import at.asitplus.awesn1.countryName
import at.asitplus.awesn1.houseIdentifier
import at.asitplus.awesn1.organization
import at.asitplus.awesn1.organizationName
import at.asitplus.awesn1.organizationalPerson
import at.asitplus.awesn1.organizationalUnit
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope

val DistinguishedNameTest by testSuite {
    "DistinguishedName test equals and hashCode" - {
        val oids = listOf(
            KnownOIDs.countryName, KnownOIDs.country, KnownOIDs.houseIdentifier,
            KnownOIDs.organizationName, KnownOIDs.organization, KnownOIDs.organizationalUnit,
            KnownOIDs.organizationalPerson, KnownOIDs.brainpoolP512r1
        )
        withData(oids) - { first ->
            withData(oids, compact= true) { second ->
                if (first != second) {
                    val cn1 = AttributeTypeAndValue.CommonName(first.toString())
                    val cn2 = AttributeTypeAndValue.CommonName(first.toString())
                    val cn3 = AttributeTypeAndValue.CommonName(second.toString())
                    val c1 = AttributeTypeAndValue.Country(first.toString())
                    val c2 = AttributeTypeAndValue.Country(second.toString())
                    val o1 = AttributeTypeAndValue.Organization(first.toString())
                    val o2 = AttributeTypeAndValue.Organization(second.toString())
                    val ou1 = AttributeTypeAndValue.OrganizationalUnit(first.toString())
                    val ou2 = AttributeTypeAndValue.OrganizationalUnit(second.toString())
                    val ot1 = AttributeTypeAndValue(first, Asn1String.UTF8(first.toString()))
                    val ot2 = AttributeTypeAndValue(first, Asn1String.UTF8(second.toString()))
                    val ot3 = AttributeTypeAndValue(second, Asn1String.UTF8(first.toString()))
                    val ot4 = AttributeTypeAndValue(second, Asn1String.UTF8(second.toString()))

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
}