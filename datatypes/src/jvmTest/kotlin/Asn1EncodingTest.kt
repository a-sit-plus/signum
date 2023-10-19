import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.io.KmmBitSet
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.long
import io.kotest.property.checkAll
import kotlinx.datetime.Clock
import org.bouncycastle.asn1.ASN1Integer
import java.util.*

@OptIn(ExperimentalUnsignedTypes::class)
class Asn1EncodingTest : FreeSpec({


    val bitSet = KmmBitSet.fromBitString("011011100101110111")
    "Bit String" {
        val fromBitSet = Asn1BitString.fromBitSet(bitSet)
        fromBitSet.encodeToTlv().toDerHexString() shouldBe "0304066E5DC0"
        fromBitSet.toBitSet().toBitString() shouldBe "011011100101110111"
        fromBitSet.toBitSet() shouldBe bitSet
    }

    "Ans1 Number encoding" - {

        withData(15253481L, -1446230472L, 0L, 1L, -1L, -2L, -9994587L, 340281555L) {
            val bytes = (it).encodeToByteArray()

            val fromBC = ASN1Integer(it).encoded
            val long = Long.decodeFromDer(bytes)

            val encoded = Asn1Primitive(BERTags.INTEGER, bytes).derEncoded
            encoded shouldBe fromBC
            long shouldBe it
        }


        "longs" - {
            checkAll(iterations = 15000, Arb.long()) {
                val seq = asn1Sequence { long { it } }
                val decoded = (seq.nextChild() as Asn1Primitive).readLong()
                decoded shouldBe it
            }
        }

        "ints" - {
            checkAll(iterations = 15000, Arb.int()) {
                val seq = asn1Sequence { int { it } }
                val decoded = (seq.nextChild() as Asn1Primitive).readInt()
                decoded shouldBe it
            }
        }

    }

    "Parsing and encoding results in the same bytes" {
        val certBytes = Base64.getMimeDecoder()
            .decode(javaClass.classLoader.getResourceAsStream("github-com.pem").reader().readText())
        val tree = Asn1Element.parse(certBytes)
        tree.derEncoded shouldBe certBytes
    }

    "Encoding and parsing results in the same bytes" {

        val instant = Clock.System.now()

        val sequence = asn1Sequence {
            tagged(31u) {
                Asn1Primitive(BERTags.BOOLEAN, byteArrayOf(0x00))
            }
            set {
                sequence {
                    setOf {
                        printableString { "World" }
                        printableString { "Hello" }
                    }
                    set {
                        printableString { "World" }
                        printableString { "Hello" }
                        utf8String { "!!!" }
                    }

                }
            }
            asn1null()

            oid { ObjectIdentifier("1.2.603.624.97") }

            utf8String { "Foo" }
            printableString { "Bar" }

            set {
                int { 3 }
                long { -65789876543L }
                bool { false }
                bool { true }
            }
            sequence {
                asn1null()
                string { Asn1String.Numeric("12345") }
                utcTime { instant }
            }
        }

        println(sequence)

        Asn1Element.parse(sequence.derEncoded).derEncoded shouldBe sequence.derEncoded
        println(sequence.toDerHexString(lineLen = 58))
    }
})