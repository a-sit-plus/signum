package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.*
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import com.ionspin.kotlin.bignum.integer.util.fromTwosComplementByteArray
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.*
import io.kotest.property.checkAll
import kotlinx.io.Buffer
import kotlinx.io.snapshot
import org.bouncycastle.asn1.ASN1Integer
import kotlin.math.pow

class Asn1NumberEncodingTest:FreeSpec( {


    "Asn1 Number encoding" - {

        "manual" - {
            withData(
                257L,
                2f.pow(24).toLong() - 1,
                65555,
                2f.pow(24).toLong(),
                15253481L,
                -1446230472L,
                0L,
                1L,
                -1L,
                -2L,
                -9994587L,
                340281555L
            ) {
                val bytes = (it).toTwosComplementByteArray()

                val fromBC = ASN1Integer(it).encoded
                val long = Long.decodeFromAsn1ContentBytes(bytes)

                val encoded = Asn1Primitive(Asn1Element.Tag.INT, bytes).derEncoded
                encoded shouldBe fromBC
                long shouldBe it

                bytes.wrapInUnsafeSource().readTwosComplementLong(bytes.size) shouldBe it
            }
        }


        "longs" - {
            "failures: too small" - {
                checkAll(iterations = 5000, Arb.bigInt(128)) {
                    val v = BigInteger.fromLong(Long.MIN_VALUE).minus(1)
                        .minus(BigInteger.fromTwosComplementByteArray(it.toByteArray()))
                    shouldThrow<Asn1Exception> { Asn1.Int(v).decodeToLong() }
                }
            }
            "failures: too large" - {
                checkAll(iterations = 5000, Arb.bigInt(128)) {
                    val v = BigInteger.fromLong(Long.MAX_VALUE).plus(1)
                        .plus(BigInteger.fromTwosComplementByteArray(it.toByteArray()))
                    shouldThrow<Asn1Exception> { Asn1.Int(v).decodeToLong() }
                }
            }
            "successes" - {
                checkAll(iterations = 150000, Arb.long()) {
                    val seq = Asn1.Sequence { +Asn1.Int(it) }
                    val decoded = (seq.nextChild() as Asn1Primitive).decodeToLong()
                    decoded shouldBe it

                    Asn1.Int(it).derEncoded shouldBe ASN1Integer(it).encoded

                    val toTwosComplementByteArray = it.toTwosComplementByteArray()
                    toTwosComplementByteArray.wrapInUnsafeSource()
                        .readTwosComplementLong(toTwosComplementByteArray.size) shouldBe it
                    Buffer().apply { writeTwosComplementLong(it) }.snapshot()
                        .toByteArray() shouldBe toTwosComplementByteArray

                }
            }
        }

        "ints" - {
            "failures: too small" - {
                checkAll(iterations = 5000, Arb.long(Long.MIN_VALUE..<Int.MIN_VALUE.toLong())) {
                    shouldThrow<Asn1Exception> { Asn1.Int(it).decodeToInt() }
                }
            }
            "failures: too large" - {
                checkAll(iterations = 5000, Arb.long(Int.MAX_VALUE.toLong() + 1..<Long.MAX_VALUE)) {
                    shouldThrow<Asn1Exception> { Asn1.Int(it).decodeToInt() }
                }
            }
            "successes" - {
                checkAll(iterations = 75000, Arb.int()) {
                    val seq = Asn1.Sequence { +Asn1.Int(it) }
                    val decoded = (seq.nextChild() as Asn1Primitive).decodeToInt()
                    decoded shouldBe it

                    Asn1.Int(it).derEncoded shouldBe ASN1Integer(it.toLong()).encoded
                    val twosComplementByteArray = it.toTwosComplementByteArray()
                    twosComplementByteArray.wrapInUnsafeSource()
                        .readTwosComplementInt(twosComplementByteArray.size) shouldBe it
                    twosComplementByteArray.wrapInUnsafeSource()
                        .readTwosComplementLong(twosComplementByteArray.size) shouldBe it
                }
            }
        }

        "unsigned ints" - {
            "failures: negative" - {
                checkAll(iterations = 5000, Arb.long(Long.MIN_VALUE..<0)) {
                    shouldThrow<Asn1Exception> { Asn1.Int(it).decodeToUInt() }
                }
            }
            "failures: too large" - {
                checkAll(iterations = 5000, Arb.long(UInt.MAX_VALUE.toLong() + 1..Long.MAX_VALUE)) {
                    shouldThrow<Asn1Exception> { Asn1.Int(it).decodeToUInt() }
                }
            }
            "successes" - {
                checkAll(iterations = 75000, Arb.uInt()) {
                    val seq = Asn1.Sequence { +Asn1.Int(it) }
                    val decoded = (seq.nextChild() as Asn1Primitive).decodeToUInt()
                    decoded shouldBe it

                    Asn1.Int(it).derEncoded shouldBe ASN1Integer(it.toBigInteger().toJavaBigInteger()).encoded
                    val twosComplementByteArray = it.toTwosComplementByteArray()
                    twosComplementByteArray.wrapInUnsafeSource()
                        .readTwosComplementUInt(twosComplementByteArray.size) shouldBe it
                    twosComplementByteArray.wrapInUnsafeSource()
                        .readTwosComplementULong(twosComplementByteArray.size) shouldBe it.toULong()
                }
            }
        }

        "unsigned longs" - {

            "manual" - {
                withData(
                    2f.pow(24).toULong() - 1u,
                    256uL,
                    65555uL,
                    2f.pow(24).toULong(),
                    255uL,
                    360uL,
                    4113774321109173852uL
                ) {
                    val bytes = (it).toTwosComplementByteArray()
                    bytes.wrapInUnsafeSource().readTwosComplementULong(bytes.size) shouldBe it
                }
            }

            "failures: negative" - {
                checkAll(iterations = 5000, Arb.long(Long.MIN_VALUE..<0)) {
                    shouldThrow<Asn1Exception> { Asn1.Int(it).decodeToULong() }
                }
            }
            "failures: too large" - {
                checkAll(iterations = 5000, Arb.bigInt(128)) {
                    val byteArray = it.toByteArray()
                    val v = BigInteger.fromULong(ULong.MAX_VALUE).plus(1).plus(
                        BigInteger.fromTwosComplementByteArray(
                            byteArray
                        )
                    )
                    val asn1Primitive = Asn1.Int(v)
                    shouldThrow<Asn1Exception> { asn1Primitive.decodeToULong() }
                }
            }
            "successes" - {
                checkAll(iterations = 75000, Arb.uLong()) {
                    val seq = Asn1.Sequence { +Asn1.Int(it) }
                    val decoded = (seq.nextChild() as Asn1Primitive).decodeToULong()
                    decoded shouldBe it

                    Asn1.Int(it).derEncoded shouldBe ASN1Integer(it.toBigInteger().toJavaBigInteger()).encoded
                    val twosComplementByteArray = it.toTwosComplementByteArray()
                    twosComplementByteArray.wrapInUnsafeSource()
                        .readTwosComplementULong(twosComplementByteArray.size) shouldBe it
                }
            }
        }

    }

})