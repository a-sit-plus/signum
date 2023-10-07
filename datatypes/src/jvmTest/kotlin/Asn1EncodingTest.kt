import at.asitplus.crypto.datatypes.asn1.Asn1TreeBuilder
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import java.util.*

class Asn1EncodingTest : FreeSpec({
    val certBytes = Base64.getMimeDecoder()
        .decode(javaClass.classLoader.getResourceAsStream("certWithSkiAndExt.pem").reader().readText())


    "Parsing works" {
        val tree = Asn1TreeBuilder(certBytes).readAll()
        tree shouldHaveSize 1
        tree.first().derEncoded shouldBe certBytes
    }

})