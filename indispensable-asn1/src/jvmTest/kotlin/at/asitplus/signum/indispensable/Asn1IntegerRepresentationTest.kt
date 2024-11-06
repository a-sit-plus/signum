package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.decodeAsn1VarBigInt
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.integer.util.toTwosComplementByteArray
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.bigInt
import io.kotest.property.checkAll
import java.math.BigInteger
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalUuidApi::class)
class Asn1IntegerRepresentationTest : FreeSpec({

    "Manual" - {
        withData("1027", "256", "1", "3", "8", "127", "128", "255", "512", "1024") {
            val javaBigInt = BigInteger(it)
            val ref = javaBigInt.toString()
            val own = VarUInt(ref)
            val ownBytes = own.bytes
            val javaBytes = javaBigInt.toByteArray()
            val bigitBytes = javaBytes.dropWhile { it == 0.toByte() && javaBytes.size > 1 }.map { it.toUByte() }


            own.toString() shouldBe ref
            ownBytes shouldBe bigitBytes

            val varInt = own.toAsn1VarInt()
            val refVarint =
                com.ionspin.kotlin.bignum.integer.BigInteger.parseString(javaBigInt.toString()).toAsn1VarInt()
            varInt shouldBe refVarint
            refVarint.decodeAsn1VarBigInt()
            refVarint.decodeAsn1VarBigInt().first.uint shouldBe own

        }
    }


    "Automated" - {
        checkAll(Arb.bigInt(1, 65)) {
            val javaBigInt = it.abs()
            val ref = javaBigInt.toString()
            val own = VarUInt(ref)
            val ownBytes = own.bytes
            val javaBytes = javaBigInt.toByteArray()
            val bigitBytes = javaBytes.dropWhile { it == 0.toByte() && javaBytes.size > 1 }.map { it.toUByte() }

            own.toString() shouldBe ref
            ownBytes shouldBe bigitBytes
            own.toAsn1VarInt() shouldBe com.ionspin.kotlin.bignum.integer.BigInteger.parseString(javaBigInt.toString())
                .toAsn1VarInt()

        }
    }

    "UUIDs" - {
        withData(nameFn = { it.toHexString() }, List<Uuid>(100) { Uuid.random() }) {
            val hex = it.toHexString().uppercase()
            val bigint = com.ionspin.kotlin.bignum.integer.BigInteger.fromByteArray(it.toByteArray(), Sign.POSITIVE)
            val own = VarUInt(it.toByteArray())
        }
    }

    "TwosComplement" - {

        "manual" - {
            withData( "-24519924295662886907187464938912882392492723242957571281","-1457686090107523769986476796769829633039407019130", "-18440417236681064435", "-1") {
                val neg = com.ionspin.kotlin.bignum.integer.BigInteger.parseString(it)
                val ownNeg = Asn1Integer.fromDecimalString(neg.toString())
                withClue(neg.toString()) {
                    ownNeg.toString() shouldBe neg.toString()
                    ownNeg.twosComplement() shouldBe neg.toTwosComplementByteArray()
                }
            }
        }

        "automated" - {
            checkAll(Arb.bigInt(1, 349)) {
                val pos = com.ionspin.kotlin.bignum.integer.BigInteger.fromByteArray(it.toByteArray(), Sign.POSITIVE)
                val neg = com.ionspin.kotlin.bignum.integer.BigInteger.fromByteArray(it.toByteArray(), Sign.NEGATIVE)

                val ownPos = Asn1Integer.fromDecimalString(pos.toString())
                ownPos.toString() shouldBe pos.toString()
                ownPos.twosComplement() shouldBe pos.toTwosComplementByteArray()
                val ownNeg = Asn1Integer.fromDecimalString(neg.toString())
                withClue(neg.toString()) {
                    ownNeg.toString() shouldBe neg.toString()
                    ownNeg.twosComplement() shouldBe neg.toTwosComplementByteArray()
                }
                Asn1Integer.fromTwosComplement(ownPos.twosComplement()) shouldBe ownPos
                Asn1Integer.fromTwosComplement(ownNeg.twosComplement()) shouldBe ownNeg
            }
        }
    }
})

