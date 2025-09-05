package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.decodeToAsn1Integer
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1Primitive
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.testballoon.checkAllSuites
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import de.infix.testBalloon.framework.testSuite

import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeTypeOf
import io.kotest.property.Arb
import io.kotest.property.arbitrary.*
import io.kotest.property.checkAll
import java.math.BigInteger as JavaBigInteger

private fun UByteArray.stripLeadingZeros() =
    when (val i = indexOfFirst { it != 0x00u.toUByte() }) {
        -1 -> ubyteArrayOf(0x00u)
        0 -> this
        else -> copyOfRange(i, size)
    }

private fun ByteArray.stripLeadingZeros() = asUByteArray().stripLeadingZeros()

val Asn1IntegerTest by testSuite {
    "Encoding: Negative" {
        val result =
            Asn1Integer(-20).encodeToAsn1Primitive()
        result.toDerHexString() shouldBe "02 01 EC".replace(" ", "")
    }
    "Encoding: Large Positive" {
        val result =
            Asn1Integer(0xEC).encodeToAsn1Primitive()
        result.toDerHexString() shouldBe "02 02 00 EC".replace(" ", "")
    }
    "Decoding: Negative" {
        val result =
            (Asn1Element.parse(ubyteArrayOf(0x02u, 0x01u, 0xECu).toByteArray()) as Asn1Primitive)
                .decodeToAsn1Integer()
        result shouldBe Asn1Integer(-20)
    }
    "Decoding: Large Positive" {
        val result =
            (Asn1Element.parse(ubyteArrayOf(0x02u, 0x02u, 0x00u, 0xECu).toByteArray()) as Asn1Primitive)
                .decodeToAsn1Integer()
        result shouldBe Asn1Integer(0xEC)
    }
    "From String: Negative Zero" {
        Asn1Integer.fromDecimalString("-0").let {
            it.shouldBeTypeOf<Asn1Integer.Positive>()
            it.isZero() shouldBe true
            it shouldBe Asn1Integer(0)
            it shouldBe Asn1Integer.ZERO
            it.magnitude shouldBe byteArrayOf(0x00)
        }
    }
    "UVarInt Operations" - {
        "Fixed values" - {
            "XOR producing two zero high bytes" {
                (
                        VarUInt(ubyteArrayOf(0x80u, 0x7Fu, 0x03u)) xor
                                VarUInt(ubyteArrayOf(0x80u, 0x7Fu, 0x05u))
                        ).words shouldBe ubyteArrayOf(0x06u)
            }
            "AND producing two zero high bytes" {
                (
                        VarUInt(ubyteArrayOf(0x80u, 0x4Fu, 0x15u)) and
                                VarUInt(ubyteArrayOf(0x03u, 0xA0u, 0x34u))
                        ).words shouldBe ubyteArrayOf(0x14u)
            }
            "Left Shift producing a zero high byte" {
                VarUInt(ubyteArrayOf(0x18u, 0x43u)).shl(3).words shouldBe ubyteArrayOf(0xC2u, 0x18u)
            }
            "Right Shift producing a zero high byte" {
                VarUInt(ubyteArrayOf(0x05u, 0xFCu)).shr(3).words shouldBe ubyteArrayOf(0xBFu)
            }
        }
        "Random values" - {
            checkAllSuites(iterations = 100, Arb.byteArray(Arb.int(100, 200), Arb.byte())) {
                val bigint = JavaBigInteger(1, it)
                val varuint = VarUInt(it)
                "Left Bitshift" {
                    checkAll(iterations = 50, Arb.nonNegativeInt(max = 128)) { i ->
                        varuint.shl(i).words shouldBe bigint.shiftLeft(i).toByteArray().stripLeadingZeros()
                    }
                }
                "Right Bitshift" {
                    checkAll(iterations = 50, Arb.nonNegativeInt()) { i ->
                        varuint.shr(i).words shouldBe bigint.shiftRight(i).toByteArray().stripLeadingZeros()
                    }
                }
                "Binary Operators" {
                    checkAll(iterations = 10, Arb.byteArray(Arb.int(100, 200), Arb.byte())) { it2 ->
                        val bigint2 = JavaBigInteger(1, it2)
                        val varuint2 = VarUInt(it2)
                        varuint.xor(varuint2).words shouldBe bigint.xor(bigint2).toByteArray().stripLeadingZeros()
                        varuint.or(varuint2).words shouldBe bigint.or(bigint2).toByteArray().stripLeadingZeros()
                        varuint.and(varuint2).words shouldBe bigint.and(bigint2).toByteArray().stripLeadingZeros()
                    }
                }
            }
        }
    }
    "Java BigInteger <-> Asn1Integer" - {
        "Specific values" - {
            withData(
                nameFn = { it.first }, listOf(
                    Triple("Zero", JavaBigInteger.ZERO, Asn1Integer(0)),
                    Triple("Zero from Long", JavaBigInteger.valueOf(0L), Asn1Integer(0uL)),
                    Triple("One", JavaBigInteger.ONE, Asn1Integer(1)),
                    Triple("Negative One", JavaBigInteger.ONE.unaryMinus(), Asn1Integer(-1))
                )
            )
            { (_, bigint, asn1int) ->
                bigint.toAsn1Integer() shouldBe asn1int
                asn1int.toJavaBigInteger() shouldBe bigint
            }
        }
        "Generic values" {
            checkAll(iterations = 2500, Arb.positiveLong()) {
                val bigint = JavaBigInteger.valueOf(it)
                val asn1int = Asn1Integer(it)
                asn1int.shouldBeTypeOf<Asn1Integer.Positive>()
                bigint.toAsn1Integer() shouldBe asn1int
                asn1int.toJavaBigInteger() shouldBe bigint
            }
            checkAll(iterations = 2500, Arb.nonPositiveLong()) {
                val bigint = JavaBigInteger.valueOf(it)
                val asn1int = Asn1Integer(it)
                if (it < 0)
                    asn1int.shouldBeTypeOf<Asn1Integer.Negative>()
                bigint.toAsn1Integer() shouldBe asn1int
                asn1int.toJavaBigInteger() shouldBe bigint
            }
            checkAll(iterations = 500, Arb.byteArray(Arb.int(1500..2500), Arb.byte())) {
                val bigint = JavaBigInteger(-1, it)
                val asn1int = Asn1Integer.fromByteArray(it, Asn1Integer.Sign.NEGATIVE)
                if (!asn1int.isZero())
                    asn1int.shouldBeTypeOf<Asn1Integer.Negative>()
                bigint.toAsn1Integer() shouldBe asn1int
                asn1int.toJavaBigInteger() shouldBe bigint
            }
            checkAll(iterations = 1000, Arb.byteArray(Arb.int(1500..2500), Arb.byte())) {
                val bigint = JavaBigInteger(1, it)
                val asn1int = Asn1Integer.fromUnsignedByteArray(it)
                asn1int.shouldBeTypeOf<Asn1Integer.Positive>()
                bigint.toAsn1Integer() shouldBe asn1int
                asn1int.toJavaBigInteger() shouldBe bigint
            }
        }
        "Equality" - {
            val arb = Arb.byteArray(Arb.int(1500..2500), Arb.byte())
            val randoms = List<ByteArray>(10) { arb.next() }

            withDataSuites({ "$it" }, data = randoms) { outer: ByteArray ->
                val i1 = Asn1Integer.fromUnsignedByteArray(outer)
                i1 shouldBe Asn1Integer.fromUnsignedByteArray(outer)
                withData(data = randoms.filterNot { it contentEquals outer }) { inner: ByteArray ->
                    i1 shouldNotBe Asn1Integer.fromUnsignedByteArray(inner)
                }
            }
        }
    }
}
