import at.asitplus.crypto.datatypes.asn1.*
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import kotlinx.datetime.Clock
import java.util.*

@OptIn(ExperimentalUnsignedTypes::class)
class Asn1EncodingTest : FreeSpec({
    val certBytes = Base64.getMimeDecoder()
        .decode(javaClass.classLoader.getResourceAsStream("certWithSkiAndExt.pem").reader().readText())


    "Parsing and encoding results in the same bytes" {
        val tree = Asn1Element.parse(certBytes)
        tree.derEncoded shouldBe certBytes
    }

    "Old and new encoder produce the same bytes" {

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

            oid { ObjectIdentifier("1.2.60873.543.65.2324.97") }

            utf8String { "Foo" }
            printableString { "Bar" }

            set {
                int { 3 }
                long { 123456789876543L }
                bool { false }
                bool { true }
            }
            sequence {
                asn1null()
                hexEncoded { "CAFEBABE" }
                hexEncoded { "BADDAD" }
                utcTime { instant }
            }
        }

        println(sequence)
        println("DER-encoded: ${sequence.toDerHexString()}")
    }
})