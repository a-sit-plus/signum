import at.asitplus.crypto.datatypes.asn1.Asn1Encodable
import at.asitplus.crypto.datatypes.asn1.asn1Sequence
import at.asitplus.crypto.datatypes.asn1.parse
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import kotlinx.datetime.Clock
import java.util.Base64

class Asn1EncodingTest : FreeSpec({
    val certBytes = Base64.getMimeDecoder()
        .decode(javaClass.classLoader.getResourceAsStream("certWithSkiAndExt.pem").reader().readText())


    "Parsing and encoding results in the same bytes" {
        val tree = Asn1Encodable.parse(certBytes)
        tree.derEncoded shouldBe certBytes
    }

    "Old and new encoder produce the same bytes" {

        val instant = Clock.System.now()

        val new = asn1Sequence {
            asn1null()
            asn1null()
            asn1null()
            asn1null()

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
    }
})