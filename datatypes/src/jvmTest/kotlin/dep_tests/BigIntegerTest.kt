package dep_tests

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlin.random.Random

class BigIntegerTest : FreeSpec({
    "BigInteger" - {
        "equals & hashCode" {
            val v1 = BigInteger(42)
            v1 shouldBe v1
            v1.hashCode() shouldBe v1.hashCode()

            val v11 = BigInteger(42)
            v11 shouldBe v1
            v11.hashCode() shouldBe v1.hashCode()

            val v2 = BigInteger(21)
            v2 shouldNotBe v1
            v2.hashCode() shouldNotBe v1.hashCode()

            (v2 < v1) shouldBe true
            (v1 < v2) shouldNotBe true
        }
    }
    "ModularBigInteger" - {
        "equals & hashcode" {
            val creator = ModularBigInteger.creatorForModulo(7)

            val v1 = creator.fromInt(6) /* 6 mod 7 = 6 */
            val v11 = creator.fromInt(13) /* 13 mod 7 = 6 */
            v1 shouldBe v1
            v1.hashCode() shouldBe v1.hashCode()
            v11 shouldBe v1
            v11.hashCode() shouldBe v1.hashCode()

            val v2 = creator.fromInt(12) /* 12 mod 7 = 5 */
            v2 shouldNotBe v1
            v2.hashCode() shouldNotBe v1.hashCode()

            val v3 = v2 - v1 /* 5 - 6 = -1, -1 mod 7 == 6 */
            v3 shouldBe v1
            v3.hashCode() shouldBe v1.hashCode()
        }

        "additive inverse".config(invocations = 5000) {
            val modulus = BigInteger.fromByteArray(Random.nextBytes(32), Sign.POSITIVE)
            val creator = ModularBigInteger.creatorForModulo(modulus)
            val first = creator.fromBigInteger(BigInteger.fromByteArray(Random.nextBytes(32), Sign.POSITIVE))
            val second = creator.fromBigInteger(BigInteger.fromByteArray(Random.nextBytes(32), Sign.POSITIVE))

            first + (-first) shouldBe 0
            second + (-second) shouldBe 0
            first + (-second) shouldBe first - second
            (-second) + first shouldBe first - second
            (-first) + second shouldBe second - first
            second + (-first) shouldBe second - first
            -(-first) shouldBe first
            -(-second) shouldBe second
        }
        "multiplicative inverse".config(invocations = 500) {
            val modulus = generateSequence {
                BigInteger.fromByteArray(Random.nextBytes(32), Sign.POSITIVE)
            }.filter { it.toJavaBigInteger().isProbablePrime(128) }.first()
            val creator = ModularBigInteger.creatorForModulo(modulus)
            val first = creator.fromBigInteger(BigInteger.fromByteArray(Random.nextBytes(32), Sign.POSITIVE))
            val second = creator.fromBigInteger(BigInteger.fromByteArray(Random.nextBytes(32), Sign.POSITIVE))

            val firstInv = first.inverse()
            val secondInv = second.inverse()
            first * firstInv shouldBe 1
            second * secondInv shouldBe 1
            (first * secondInv) * second shouldBe first
            first * (firstInv * second) shouldBe second
            second * (first * secondInv) shouldBe first
            secondInv * (first * second) shouldBe first
            (first * second) * firstInv shouldBe second
            (second * firstInv) * first shouldBe second
        }
    }
})
