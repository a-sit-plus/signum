import at.asitplus.crypto.datatypes.X509Certificate
import at.asitplus.crypto.datatypes.asn1.Asn1Encodable
import at.asitplus.crypto.datatypes.asn1.Asn1Sequence
import at.asitplus.crypto.datatypes.asn1.parse
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.util.Base64
import java.security.cert.X509Certificate as JcaCertificate

private val json = Json { prettyPrint = true }

class X509CertParserTest : FreeSpec({

    "Real Certificates" - {
        withData("certWithSkiAndExt.pem", "digicert-root.pem", "github-com.pem", "cert-times.pem") { crt ->
            val certBytes = Base64.getMimeDecoder()
                .decode(javaClass.classLoader.getResourceAsStream(crt).reader().readText())
            val jcaCert = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(certBytes)) as JcaCertificate

            println(jcaCert.encoded.encodeToString(Base16))

            val parsedCert = X509Certificate.decodeFromTlv(Asn1Encodable.parse(certBytes) as Asn1Sequence)
            println(json.encodeToString(parsedCert))
            println(parsedCert.encodeToTlv().derEncoded.encodeToString(Base16()))

            withClue(
                "Expect: ${jcaCert.encoded.encodeToString(Base16)}\n" +
                        "Actual: ${parsedCert.encodeToTlv().derEncoded.encodeToString(Base16)}"
            ) {
                parsedCert.encodeToTlv().derEncoded shouldBe jcaCert.encoded
            }
        }
    }

})