package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.decodeAsn1VarBigInt
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import com.ionspin.kotlin.bignum.integer.util.toTwosComplementByteArray
import io.kotest.assertions.withClue
import at.asitplus.test.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.positiveInt
import io.kotest.property.checkAll
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalUuidApi::class)
class Asn1IntegerRepresentationTest : FreeSpec({

    "Manual" - {
        withData("1027", "256", "1", "3", "8", "127", "128", "255", "512", "1024") {
            val bigInt = BigInteger.parseString(it)
            val ref = bigInt.toString()
            val own = VarUInt(ref)
            val ownBytes = own.bytes
            val javaBytes = bigInt.toByteArray()
            val bigitBytes = javaBytes.dropWhile { it == 0.toByte() && javaBytes.size > 1 }.map { it.toUByte() }


            own.toString() shouldBe ref
            ownBytes shouldBe bigitBytes

            val varInt = own.toAsn1VarInt()
            val refVarint = BigInteger.parseString(bigInt.toString()).toAsn1VarInt()
            varInt shouldBe refVarint
            refVarint.decodeAsn1VarBigInt().first.uint.words shouldBe own.words
        }
    }


    "Automated" - {
        checkAll(Arb.byteArray(Arb.positiveInt(65), Arb.byte())) {
            val bigInt = BigInteger.fromByteArray(it, Sign.POSITIVE)
            val ref = bigInt.toString()
            val own = VarUInt(ref)
            val ownBytes = own.bytes
            val javaBytes = bigInt.toByteArray()
            val bigitBytes = javaBytes.dropWhile { it == 0.toByte() && javaBytes.size > 1 }.map { it.toUByte() }

            own.toString() shouldBe ref
            ownBytes shouldBe bigitBytes
            own.toAsn1VarInt() shouldBe BigInteger.parseString(bigInt.toString()).toAsn1VarInt()

        }
    }

    "UUIDs" - {
        withData(nameFn = { it.toHexString() }, List<Uuid>(100) { Uuid.random() }) {
            val bigint = BigInteger.fromByteArray(it.toByteArray(), Sign.POSITIVE).toJavaBigInteger()
            val own = Asn1Integer.fromUnsignedByteArray(it.toByteArray()).toJavaBigInteger()
            own shouldBe bigint
        }
    }

    "TwosComplement" - {

        "manual" - {
            withData(
                "-24519924295662886907187464938912882392492723242957571281",
                "-1457686090107523769986476796769829633039407019130",
                "-18440417236681064435",
                "-1"
            ) {
                val neg = BigInteger.parseString(it)
                val ownNeg = Asn1Integer.fromDecimalString(neg.toString())
                withClue(neg.toString()) {
                    ownNeg.toString() shouldBe neg.toString()
                    ownNeg.twosComplement() shouldBe neg.toTwosComplementByteArray()
                }
            }
        }

        "automated" - {
            checkAll(Arb.byteArray(Arb.positiveInt(349), Arb.byte())) {
                val pos = BigInteger.fromByteArray(it, Sign.POSITIVE)
                val neg = BigInteger.fromByteArray(it, Sign.NEGATIVE)

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
