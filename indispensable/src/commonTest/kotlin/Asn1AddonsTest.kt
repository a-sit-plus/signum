package at.asitplus.signum
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.testballoon.checkAllTests
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.testSuite
import io.kotest.common.Platform
import io.kotest.common.platform
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeTypeOf
import io.kotest.property.Arb
import io.kotest.property.arbitrary.*
import io.kotest.property.checkAll
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

val Asn1AddonsTest by testSuite(testConfig = TestConfig.testScope(isEnabled = true, timeout = 20.minutes)) {
   
    "BigInteger Encoding: Negative" {
        val result =
            BigInteger(-20).encodeToAsn1Primitive()
        result.toDerHexString() shouldBe "02 01 EC".replace(" ", "")
    }
    "BigInteger Encoding: Large Positive" {
        val result =
            BigInteger(0xEC).encodeToAsn1Primitive()
        result.toDerHexString() shouldBe "02 02 00 EC".replace(" ", "")
    }
    "BigInteger Decoding: Negative" {
        val result =
            (Asn1Element.parse(ubyteArrayOf(0x02u, 0x01u, 0xECu).toByteArray()) as Asn1Primitive)
                .decodeToBigInteger()
        result shouldBe BigInteger(-20)
    }
    "BigInteger Decoding: Large Positive" {
        val result =
            (Asn1Element.parse(ubyteArrayOf(0x02u, 0x02u, 0x00u, 0xECu).toByteArray()) as Asn1Primitive)
                .decodeToBigInteger()
        result shouldBe BigInteger(0xEC)
    }

    if (!listOf(Platform.JS, Platform.WasmJs).contains(platform)) {
        "BigInteger <-> Asn1Integer conversion" - {
            "Specific values" - {
                withData(
                    nameFn = { it.first }, sequenceOf(
                        Triple("Zero", BigInteger.ZERO, Asn1Integer(0)),
                        Triple("Zero from ULong", BigInteger.fromULong(0uL), Asn1Integer(0uL)),
                        Triple("One", BigInteger.ONE, Asn1Integer(1)),
                        Triple("Negative One", BigInteger.ONE.unaryMinus(), Asn1Integer(-1))
                    )
                )
                { (_, bigint, asn1int) ->
                    bigint.toAsn1Integer() shouldBe asn1int
                    asn1int.toBigInteger() shouldBe bigint
                }
            }
            "Generic values" - {
                checkAllTests(iterations = 2500, Arb.uLong()) {
                    val bigint = BigInteger.fromULong(it)
                    val asn1int = Asn1Integer(it)
                    asn1int.shouldBeTypeOf<Asn1Integer.Positive>()
                    bigint.toAsn1Integer() shouldBe asn1int
                    asn1int.toBigInteger() shouldBe bigint
                }
                checkAllTests(iterations = 2500, Arb.nonPositiveLong()) {
                    val bigint = BigInteger.fromLong(it)
                    val asn1int = Asn1Integer(it)
                    if (it < 0)
                        asn1int.shouldBeTypeOf<Asn1Integer.Negative>()
                    bigint.toAsn1Integer() shouldBe asn1int
                    asn1int.toBigInteger() shouldBe bigint
                }
                checkAllTests(iterations = 500, Arb.byteArray(Arb.int(1500..2500), Arb.byte())) {
                    val bigint = BigInteger.fromByteArray(it, Sign.NEGATIVE)
                    val asn1int = Asn1Integer.fromByteArray(it, Asn1Integer.Sign.NEGATIVE)
                    if (!asn1int.isZero())
                        asn1int.shouldBeTypeOf<Asn1Integer.Negative>()
                    bigint.toAsn1Integer() shouldBe asn1int
                    asn1int.toBigInteger() shouldBe bigint
                }
                checkAllTests(iterations = 1000, Arb.byteArray(Arb.int(1500..2500), Arb.byte())) {
                    val bigint = BigInteger.fromByteArray(it, Sign.POSITIVE)
                    val asn1int = Asn1Integer.fromUnsignedByteArray(it)
                    asn1int.shouldBeTypeOf<Asn1Integer.Positive>()
                    bigint.toAsn1Integer() shouldBe asn1int
                    asn1int.toBigInteger() shouldBe bigint
                }
            }
        }
    }
}
