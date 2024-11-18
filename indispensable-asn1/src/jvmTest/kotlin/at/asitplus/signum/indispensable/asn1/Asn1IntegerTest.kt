package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.decodeToAsn1Integer
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1Primitive
import at.asitplus.signum.indispensable.asn1.encoding.parse
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeTypeOf
import io.kotest.property.Arb
import io.kotest.property.arbitrary.*
import io.kotest.property.checkAll
import java.math.BigInteger

class Asn1IntegerTest : FreeSpec({
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
    "Java BigInteger <-> Asn1Integer" - {
        "Specific values" - {
            withData(nameFn={it.first}, sequenceOf(
                Triple("Zero", BigInteger.ZERO, Asn1Integer(0)),
                Triple("Zero from Long", BigInteger.valueOf(0L), Asn1Integer(0uL)),
                Triple("One", BigInteger.ONE, Asn1Integer(1)),
                Triple("Negative One", BigInteger.ONE.unaryMinus(), Asn1Integer(-1))))
            { (_, bigint, asn1int) ->
                bigint.toAsn1Integer() shouldBe asn1int
                asn1int.toJavaBigInteger() shouldBe bigint
            }
        }
        "Generic values" - {
            checkAll(iterations = 2500, Arb.positiveLong()) {
                val bigint = BigInteger.valueOf(it)
                val asn1int = Asn1Integer(it)
                asn1int.shouldBeTypeOf<Asn1Integer.Positive>()
                bigint.toAsn1Integer() shouldBe asn1int
                asn1int.toJavaBigInteger() shouldBe bigint
            }
            checkAll(iterations = 2500, Arb.nonPositiveLong()) {
                val bigint = BigInteger.valueOf(it)
                val asn1int = Asn1Integer(it)
                if (it < 0)
                    asn1int.shouldBeTypeOf<Asn1Integer.Negative>()
                bigint.toAsn1Integer() shouldBe asn1int
                asn1int.toJavaBigInteger() shouldBe bigint
            }
            checkAll(iterations = 500, Arb.byteArray(Arb.int(1500..2500), Arb.byte())) {
                val bigint = BigInteger(-1, it)
                val asn1int = Asn1Integer.fromByteArray(it, Asn1Integer.Sign.NEGATIVE)
                if (!asn1int.isZero())
                    asn1int.shouldBeTypeOf<Asn1Integer.Negative>()
                bigint.toAsn1Integer() shouldBe asn1int
                asn1int.toJavaBigInteger() shouldBe bigint
            }
            checkAll(iterations = 1000, Arb.byteArray(Arb.int(1500..2500), Arb.byte())) {
                val bigint = BigInteger(1, it)
                val asn1int = Asn1Integer.fromUnsignedByteArray(it)
                asn1int.shouldBeTypeOf<Asn1Integer.Positive>()
                bigint.toAsn1Integer() shouldBe asn1int
                asn1int.toJavaBigInteger() shouldBe bigint
            }
        }
    }
})