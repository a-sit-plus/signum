import at.asitplus.crypto.datatypes.asn1.Asn1String
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class Asn1StringTest : FreeSpec ({

    val utf8 = Asn1String.UTF8("uÄasdiu3")
    val universal = Asn1String.Universal("adsa4")
    val visible = Asn1String.Visible("hkjjhk7")
    val ia5 = Asn1String.IA5("m5z5zgth")
    val teletex = Asn1String.Teletex("sdf45")
    val bmp = Asn1String.BMP("asdf")
    val printable = Asn1String.Printable("foeuzr39842?")
    val numeric = Asn1String.Numeric("56543767")

    val utf81 = Asn1String.UTF8("ud3Äasdiu3")
    val universal1 = Asn1String.Universal("a32dsa4")
    val teletex1 = Asn1String.Teletex("sdfsad45")

    val allAsn1Strings:List<Asn1String> = listOf(utf8, universal, visible, ia5, teletex, bmp, printable, numeric, utf81, universal1, teletex1)

    "Asn1Strings equals and hashCode" {
        val listIterator = allAsn1Strings.iterator()
        var integer = 0
        while (listIterator.hasNext()) {
            val item = listIterator.next()
            var integerOther = 0
            allAsn1Strings.forEach { other ->
                if(integer == integerOther) {
                    item shouldBe other
                    item.hashCode() shouldBe other.hashCode()
                }
                else {
                    item shouldNotBe other
                    item.hashCode() shouldNotBe other.hashCode()
                }
                integerOther++
            }
            integer++
        }
    }
})