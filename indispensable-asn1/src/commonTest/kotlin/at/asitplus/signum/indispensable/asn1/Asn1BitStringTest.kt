package at.asitplus.signum.indispensable.asn1

import at.asitplus.test.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class Asn1BitStringTest : FreeSpec({

    val bitSet1 = BitSet.fromBitString("011011100101110111")
    val bitSet2 = BitSet.fromBitString("011011100101110111")
    val bitSet3 = BitSet.fromBitString("011011100101110101")

    "Bit String Test" {
        val fromBitSet1 = Asn1BitString(bitSet1)
        val fromBitSet2 = Asn1BitString(bitSet2)
        val fromBitSet3 = Asn1BitString(bitSet3)
        fromBitSet1 shouldBe fromBitSet1
        fromBitSet1 shouldBe fromBitSet2
        fromBitSet1 shouldNotBe fromBitSet3
        fromBitSet1.hashCode() shouldBe fromBitSet1.hashCode()
        fromBitSet1.hashCode() shouldBe fromBitSet2.hashCode()
        fromBitSet1.hashCode() shouldNotBe fromBitSet3.hashCode()
    }
})