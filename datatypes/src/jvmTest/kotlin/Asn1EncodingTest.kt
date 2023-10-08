import at.asitplus.crypto.datatypes.Asn1String
import at.asitplus.crypto.datatypes.DistingushedName
import at.asitplus.crypto.datatypes.asn1.Asn1StructureReader
import at.asitplus.crypto.datatypes.asn1.asn1Sequence
import at.asitplus.crypto.datatypes.asn1.legacySequence
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import kotlinx.datetime.Clock
import java.util.*

class Asn1EncodingTest : FreeSpec({
    val certBytes = Base64.getMimeDecoder()
        .decode(javaClass.classLoader.getResourceAsStream("certWithSkiAndExt.pem").reader().readText())


    "Parsing and encoding results in the same bytes" {
        val tree = Asn1StructureReader(certBytes).readAll()
        tree shouldHaveSize 1
        tree.first().derEncoded shouldBe certBytes
    }

    "Old and new encoder produce the same bytes" {

        val instant = Clock.System.now()

        val new = asn1Sequence {
            asn1null()
            asn1null()
            distinguishedName {
                DistingushedName.CommonName(Asn1String.Printable("Oklahoma"))
            }
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
                oid { "CAFEBABE" }
                oid { "BADDAD" }
                utcTime { instant }
            }

        }

        val legacy = legacySequence {
            asn1null()
            asn1null()
            distinguishedName {
                DistingushedName.CommonName(Asn1String.Printable("Oklahoma"))
            }
            asn1null()
            asn1null()

            utf8String { "Foo" }
            printableString { "Bar" }

            set {
                bool { false }
                bool { true }
                int { 3 }
                long { 123456789876543L }
            }
            sequence {
                asn1null()
                oid { "CAFEBABE" }
                oid { "BADDAD" }
                utcTime { instant }
            }
        }

        legacy shouldBe new.derEncoded

        println(new)


    }
})