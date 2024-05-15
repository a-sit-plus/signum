package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.*
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class Asn1IntegerTest : FreeSpec({
    "Encoding: Negative" {
        val result =
            BigInteger(-20).encodeToTlv()
        result.toDerHexString() shouldBe "02 01 EC".replace(" ", "")
    }
    "Encoding: Large Positive" {
        val result =
            BigInteger(0xEC).encodeToTlv()
        result.toDerHexString() shouldBe "02 02 00 EC".replace(" ", "")
    }
    "Decoding: Negative" {
        val result =
            (Asn1Element.parse(ubyteArrayOf(0x02u, 0x01u, 0xECu).toByteArray()) as Asn1Primitive)
                .readBigInteger()
        result shouldBe BigInteger(-20)
    }
    "Decoding: Large Positive" {
        val result =
            (Asn1Element.parse(ubyteArrayOf(0x02u, 0x02u, 0x00u, 0xECu).toByteArray()) as Asn1Primitive)
                .readBigInteger()
        result shouldBe BigInteger(0xEC)
    }
})
