package at.asitplus.signum.indispensable.asn1

import at.asitplus.test.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class Asn1StringTest : FreeSpec({

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

    val allAsn1Strings: List<Asn1String> =
        listOf(utf8, universal, visible, ia5, teletex, bmp, printable, numeric, utf81, universal1, teletex1)

    "Asn1Strings equals and hashCode" {
        allAsn1Strings.forEachIndexed { index1, asn1String1 ->
            allAsn1Strings.forEachIndexed { index2, asn1String2 ->
                if (index1 == index2) {
                    asn1String1 shouldBe asn1String2
                    asn1String1.hashCode() shouldBe asn1String2.hashCode()
                } else {
                    asn1String1 shouldNotBe asn1String2
                    asn1String1.hashCode() shouldNotBe asn1String2.hashCode()
                }
            }
        }
    }
})