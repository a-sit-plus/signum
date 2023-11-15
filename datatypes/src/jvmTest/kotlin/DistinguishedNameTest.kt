import at.asitplus.crypto.datatypes.asn1.ObjectIdentifier
import at.asitplus.crypto.datatypes.pki.DistinguishedName
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class DistinguishedNameTest : FreeSpec({
    "DistinguishedName Test" - {
        val oid1 = ObjectIdentifier("1.3.311.128.1.4.99991.9311.21.20").encodeToTlv()
        val oid2 = ObjectIdentifier("1.3.311.128.1.4.99991.9311.21.21").encodeToTlv()
        val dn1 = DistinguishedName.CommonName(oid1)
        val dn2 = DistinguishedName.CommonName(oid1)
        val dn3 = DistinguishedName.CommonName(oid2)
        val dn4 = DistinguishedName.Organization(oid1)

        "equals()" - {

            "match" {
                dn1 shouldBe dn2
            }

            "mismatch" {
                dn1 shouldNotBe dn3
                dn1 shouldNotBe dn4
            }
        }

        "hashCode()" {
            dn1.hashCode() shouldBe dn1.hashCode()
            dn1.hashCode() shouldBe dn2.hashCode()
            dn1.hashCode() shouldNotBe dn3.hashCode()
            dn1.hashCode() shouldNotBe dn4.hashCode()
        }

    }
})