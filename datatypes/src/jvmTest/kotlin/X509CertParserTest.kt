import at.asitplus.crypto.datatypes.X509Certificate
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.util.*
import java.security.cert.X509Certificate as JcaCertificate

class X509CertParserTest : FreeSpec({
    val certBytes = Base64.getMimeDecoder()
        .decode(javaClass.classLoader.getResourceAsStream("certWithSkiAndExt.pem").reader().readText())
    val jcaCert = CertificateFactory.getInstance("X.509").generateCertificate(
        ByteArrayInputStream(
            certBytes
        )
    ) as JcaCertificate

    "Certificate can be parsed" - {
        println(jcaCert.encoded.encodeToString(Base16))
        val parsedCert = X509Certificate.decodeFromDer(certBytes)
        println(Json { prettyPrint = true }.encodeToString(parsedCert))
        println(parsedCert.encodeToDer().encodeToString(Base16()))
        "and encoded to match the original bytes" {
            parsedCert.encodeToDer() shouldBe jcaCert.encoded
        }
        "also matches using new encoder" {
            parsedCert.encodeToTlv().derEncoded shouldBe jcaCert.encoded
        }
    }


})