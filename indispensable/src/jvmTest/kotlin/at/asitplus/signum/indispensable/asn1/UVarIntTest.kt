package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.decodeAsn1VarBigInt
import at.asitplus.signum.indispensable.asn1.encoding.decodeAsn1VarUInt
import at.asitplus.signum.indispensable.asn1.encoding.decodeAsn1VarULong
import at.asitplus.signum.indispensable.asn1.encoding.toAsn1VarInt
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.bigInt
import io.kotest.property.arbitrary.uInt
import io.kotest.property.arbitrary.uLong
import io.kotest.property.checkAll
import kotlin.random.Random

class UVarIntTest : FreeSpec({

    "UInts with trailing bytes" - {
        "manual" {
            byteArrayOf(65, 0, 0, 0).decodeAsn1VarUInt().first shouldBe 65u
        }
        "automated -" {
            checkAll(Arb.uInt()) { int ->
                (int.toAsn1VarInt().asList() + Random.nextBytes(8).asList()).decodeAsn1VarUInt().first shouldBe int

            }
        }
    }

    "ULongs with trailing bytes" - {
        "manual" {
            byteArrayOf(65, 0, 0, 0).decodeAsn1VarULong().first shouldBe 65uL
        }
        "automated -" {
            checkAll(Arb.uLong()) { long ->
                (long.toAsn1VarInt().asList() + Random.nextBytes(8).asList()).decodeAsn1VarULong().first shouldBe long

            }
        }
    }

    "BigInts" - {
        "long-capped" - {
            checkAll(Arb.uLong()) { long ->
                val uLongVarInt = long.toAsn1VarInt()
                val bigInteger = BigInteger.fromULong(long)
                val bigIntVarInt = bigInteger.toAsn1VarInt()

                bigIntVarInt shouldBe uLongVarInt

                (uLongVarInt.asList() + Random.nextBytes(8).asList()).decodeAsn1VarBigInt().first shouldBe bigInteger

            }
        }

        "larger" - {
            checkAll(Arb.bigInt(1, 1024 * 32)) { javaBigInt ->
                val bigInt = BigInteger.fromByteArray(javaBigInt.toByteArray(), Sign.POSITIVE)
                (bigInt.toAsn1VarInt().asList() + Random.nextBytes(33)
                    .asList()).decodeAsn1VarBigInt().first shouldBe bigInt
            }
        }
    }

})