package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.Asn1.BitString
import at.asitplus.signum.indispensable.asn1.Asn1.Bool
import at.asitplus.signum.indispensable.asn1.Asn1.Null
import at.asitplus.signum.indispensable.asn1.Asn1.OctetString
import at.asitplus.signum.indispensable.asn1.Asn1.OctetStringEncapsulating
import at.asitplus.signum.indispensable.asn1.Asn1.PrintableString
import at.asitplus.signum.indispensable.asn1.Asn1.ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.Asn1.UtcTime
import at.asitplus.signum.indispensable.asn1.Asn1.Utf8String
import at.asitplus.signum.indispensable.io.BitSet
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import com.ionspin.kotlin.bignum.integer.util.fromTwosComplementByteArray
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.*
import io.kotest.property.checkAll
import kotlinx.datetime.Clock
import org.bouncycastle.asn1.ASN1Integer
import java.util.*

class Asn1EncodingTest : FreeSpec({

    "Boolean" - {
        checkAll(Arb.boolean()) {
            val seq = Asn1.Sequence { +Bool(it) }
            val decoded = (seq.nextChild() as Asn1Primitive).readBool()
            decoded shouldBe it
        }
    }


    val bitSet = BitSet.fromBitString("011011100101110111")
    "Bit String" {
        val fromBitSet = Asn1BitString(bitSet)
        fromBitSet.encodeToTlv().toDerHexString() shouldBe "0304066E5DC0"
        fromBitSet.toBitSet().toBitString() shouldBe "011011100101110111"
        fromBitSet.toBitSet() shouldBe bitSet

        Asn1BitString.decodeFromTlv(Asn1.Sequence { +BitString(bitSet) }.children.first() as Asn1Primitive)
            .toBitSet() shouldBe bitSet
    }

    "OCTET STRING Test" {
        val seq = Asn1.Sequence {
            +OctetStringEncapsulating {
                +Asn1.Sequence { +Utf8String("foo") }
                +Asn1.Set { +Utf8String("bar") }
                +PrintableString("a")
            }
            +OctetString(byteArrayOf(17))

            +OctetString(
                Asn1.Set {
                    +Asn1.Int(99)
                    +OctetString(byteArrayOf(1, 2, 3))
                    +OctetStringEncapsulating {
                        +Asn1EncapsulatingOctetString(
                            listOf(
                                Asn1PrimitiveOctetString(
                                    byteArrayOf(
                                        7,
                                        6,
                                        3,
                                    )
                                )
                            )
                        )
                    }
                }.derEncoded
            )
            +ExplicitlyTagged(9u) { +Clock.System.now().encodeToAsn1UtcTime() }
            +OctetString(byteArrayOf(17, -43, 23, -12, 8, 65, 90))
            +Bool(false)
            +Bool(true)
        }
        val parsed = Asn1Element.parse(seq.derEncoded)
        parsed.shouldNotBeNull()
    }

    "Asn1 Number encoding" - {

        withData(15253481L, -1446230472L, 0L, 1L, -1L, -2L, -9994587L, 340281555L) {
            val bytes = (it).toTwosComplementByteArray()

            val fromBC = ASN1Integer(it).encoded
            val long = Long.decodeFromDerValue(bytes)

            val encoded = Asn1Primitive(Asn1Element.Tag.INT, bytes).derEncoded
            encoded shouldBe fromBC
            long shouldBe it
        }


        "longs" - {
            "failures: too small" - {
                checkAll(iterations = 5000, Arb.bigInt(128)) {
                    val v = BigInteger.fromLong(Long.MIN_VALUE).minus(1).minus(BigInteger.fromTwosComplementByteArray(it.toByteArray()))
                    shouldThrow<Asn1Exception> { Asn1.Int(v).readLong() }
                }
            }
            "failures: too large" - {
                checkAll(iterations = 5000, Arb.bigInt(128)) {
                    val v = BigInteger.fromLong(Long.MAX_VALUE).plus(1).plus(BigInteger.fromTwosComplementByteArray(it.toByteArray()))
                    shouldThrow<Asn1Exception> { Asn1.Int(v).readLong() }
                }
            }
            "successes" - {
                checkAll(iterations = 150000, Arb.long()) {
                    val seq = Asn1.Sequence { +Asn1.Int(it) }
                    val decoded = (seq.nextChild() as Asn1Primitive).readLong()
                    decoded shouldBe it

                    Asn1.Int(it).derEncoded shouldBe ASN1Integer(it).encoded
                }
            }
        }

        "ints" - {
            "failures: too small" - {
                checkAll(iterations = 5000, Arb.long(Long.MIN_VALUE..<Int.MIN_VALUE.toLong())) {
                    shouldThrow<Asn1Exception> { Asn1.Int(it).readInt() }
                }
            }
            "failures: too large" - {
                checkAll(iterations = 5000, Arb.long(Int.MAX_VALUE.toLong()+1..<Long.MAX_VALUE)) {
                    shouldThrow<Asn1Exception> { Asn1.Int(it).readInt() }
                }
            }
            "successes" - {
                checkAll(iterations = 75000, Arb.int()) {
                    val seq = Asn1.Sequence { +Asn1.Int(it) }
                    val decoded = (seq.nextChild() as Asn1Primitive).readInt()
                    decoded shouldBe it

                    Asn1.Int(it).derEncoded shouldBe ASN1Integer(it.toLong()).encoded
                }
            }
        }

        "unsigned ints" - {
            "failures: negative" - {
                checkAll(iterations = 5000, Arb.long(Long.MIN_VALUE..<0)) {
                    shouldThrow<Asn1Exception> { Asn1.Int(it).readUInt() }
                }
            }
            "failures: too large" - {
                checkAll(iterations = 5000, Arb.long(UInt.MAX_VALUE.toLong() + 1..Long.MAX_VALUE)) {
                    shouldThrow<Asn1Exception> { Asn1.Int(it).readUInt() }
                }
            }
            "successes" - {
                checkAll(iterations = 75000, Arb.uInt()) {
                    val seq = Asn1.Sequence { +Asn1.Int(it) }
                    val decoded = (seq.nextChild() as Asn1Primitive).readUInt()
                    decoded shouldBe it

                    Asn1.Int(it).derEncoded shouldBe ASN1Integer(it.toBigInteger().toJavaBigInteger()).encoded
                }
            }
        }

        "unsigned longs" - {
            "failures: negative" - {
                checkAll(iterations = 5000, Arb.long(Long.MIN_VALUE..<0)) {
                    shouldThrow<Asn1Exception> { Asn1.Int(it).readULong() }
                }
            }
            "failures: too large" - {
                checkAll(iterations = 5000, Arb.bigInt(128)) {
                    val v = BigInteger.fromULong(ULong.MAX_VALUE).plus(1).plus(BigInteger.fromTwosComplementByteArray(it.toByteArray()))
                    shouldThrow<Asn1Exception> { Asn1.Int(v).readULong() }
                }
            }
            "successes" - {
                checkAll(iterations = 75000, Arb.uLong()) {
                    val seq = Asn1.Sequence { +Asn1.Int(it) }
                    val decoded = (seq.nextChild() as Asn1Primitive).readULong()
                    decoded shouldBe it

                    Asn1.Int(it).derEncoded shouldBe ASN1Integer(it.toBigInteger().toJavaBigInteger()).encoded
                }
            }
        }

    }

    "Parsing and encoding results in the same bytes" {
        val certBytes = Base64.getMimeDecoder()
            .decode(javaClass.classLoader.getResourceAsStream("github-com.pem")!!.reader().readText())
        val tree = Asn1Element.parse(certBytes)
            tree.derEncoded shouldBe certBytes
        }


    "Old and new encoder produce the same bytes" {

        val instant = Clock.System.now()

        val sequence = Asn1.Sequence {
            +ExplicitlyTagged(1u) { +Asn1Primitive(BERTags.BOOLEAN, byteArrayOf(0x00)) }
            +Asn1.Set {
                +Asn1.Sequence {
                    +Asn1.SetOf {
                        +PrintableString("World")
                        +PrintableString("Hello")
                    }
                    +Asn1.Set {
                        +PrintableString("World")
                        +PrintableString("Hello")
                        +Utf8String("!!!")
                    }

                }
            }
            +Null()

            +ObjectIdentifier("1.2.603.624.97")

            +Utf8String("Foo")
            +PrintableString("Bar")

            +Asn1.Set {
                +Asn1.Int(3)
                +Asn1.Int(-65789876543L)
                +Bool(false)
                +Bool(true)
            }
            +Asn1.Sequence {
                +Null()
                +Asn1String.Numeric("12345")
                +UtcTime(instant)
            }
        }
        Asn1Element.parse(sequence.derEncoded).derEncoded shouldBe sequence.derEncoded
    }
})
