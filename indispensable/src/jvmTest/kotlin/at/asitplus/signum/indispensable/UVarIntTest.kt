package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.signum.indispensable.io.asBuffer
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.bigInt
import io.kotest.property.arbitrary.uInt
import io.kotest.property.arbitrary.uLong
import io.kotest.property.checkAll
import kotlinx.io.Buffer
import kotlinx.io.snapshot
import kotlinx.io.writeULong
import kotlin.random.Random

class UVarIntTest : FreeSpec({

    "UInts with trailing bytes" - {
        "manual" {
            val src = byteArrayOf(65, 0, 0, 0)
            src.decodeAsn1VarUInt().first shouldBe 65u
            val buf = src.asBuffer()
            buf.decodeAsn1VarUInt().first shouldBe 65u
            repeat(3){buf.readByte() shouldBe 0.toByte()}
            buf.exhausted().shouldBeTrue()
        }
        "automated -" {
            checkAll(Arb.uInt()) { int ->
                val rnd = Random.nextBytes(8)
                val src = int.toAsn1VarInt().asList() + rnd.asList()
                src.decodeAsn1VarUInt().first shouldBe int
                val buffer = src.toByteArray().asBuffer()
                buffer.decodeAsn1VarUInt().first shouldBe int
                rnd.forEach { it shouldBe buffer.readByte() }
                buffer.exhausted().shouldBeTrue()
            }
        }
    }

    "ULongs with trailing bytes" - {
        "manual" {
            val src = byteArrayOf(65, 0, 0, 0)
            src.decodeAsn1VarULong().first shouldBe 65uL
            val buf = src.asBuffer()
            buf.decodeAsn1VarULong().first shouldBe 65uL
            repeat(3){buf.readByte() shouldBe 0.toByte()}
            buf.exhausted().shouldBeTrue()
        }
        "automated -" {
            checkAll(Arb.uLong()) { long ->
                val rnd = Random.nextBytes(8)
                val src = long.toAsn1VarInt().asList() + rnd.asList()
                src.decodeAsn1VarULong().first shouldBe long

                val buffer = src.toByteArray().asBuffer()
                buffer.decodeAsn1VarULong().first shouldBe long
                rnd.forEach { it shouldBe buffer.readByte() }
                buffer.exhausted().shouldBeTrue()

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
                Buffer().apply { writeAsn1VarInt(bigInteger) }.snapshot().toByteArray() shouldBe bigIntVarInt
                Buffer().apply { writeAsn1VarInt(long) }.snapshot().toByteArray() shouldBe uLongVarInt

                val rnd = Random.nextBytes(8)
                val src = uLongVarInt.asList() + rnd.asList()
                src.decodeAsn1VarBigInt().first shouldBe bigInteger


                val buffer = src.toByteArray().asBuffer()
                buffer.decodeAsn1VarBigInt().first shouldBe bigInteger
                rnd.forEach { it shouldBe buffer.readByte() }
                buffer.exhausted().shouldBeTrue()

            }
        }

        "larger" - {
            checkAll(Arb.bigInt(1, 1024 * 32)) { javaBigInt ->
                val bigInt = BigInteger.fromByteArray(javaBigInt.toByteArray(), Sign.POSITIVE)
                val bigIntVarint = bigInt.toAsn1VarInt()
                val rnd = Random.nextBytes(33)
                val src = bigIntVarint.asList() + rnd
                    .asList()
                src.decodeAsn1VarBigInt().first shouldBe bigInt

                val buf = src.toByteArray().asBuffer()
                buf.decodeAsn1VarBigInt().first shouldBe bigInt
                rnd.forEach { it shouldBe buf.readByte() }
                buf.exhausted().shouldBeTrue()
            }
        }
    }

})