import at.asitplus.crypto.datatypes.X509Certificate
import at.asitplus.crypto.datatypes.asn1.Asn1Encodable
import at.asitplus.crypto.datatypes.asn1.Asn1Sequence
import at.asitplus.crypto.datatypes.asn1.parse
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileReader
import java.io.InputStream
import java.security.cert.CertificateFactory
import java.util.*
import java.security.cert.X509Certificate as JcaCertificate


private val json = Json { prettyPrint = true }

class X509CertParserTest : FreeSpec({

    "Real Certificates" - {
        withData("certWithSkiAndExt.pem", "digicert-root.pem", "github-com.pem", "cert-times.pem") { crt ->
            val certBytes = java.util.Base64.getMimeDecoder()
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

    "system trust store" - {
        val certs = File("/etc/ssl/certs").listFiles { f: File -> f.name.endsWith(".pem") }.mapNotNull {
            runCatching { convertStringToX509Cert(FileReader(it).readText()) }.getOrNull()
        }
        val pemEncodeCerts = File("/etc/ssl/certs/ca-certificates.crt").readText().split(Regex.fromLiteral("-\n-"))
            .mapNotNull {
                var pem = if (it.startsWith("-----")) it else "-$it"
                pem = if (!pem.endsWith("-----")) "$pem-" else pem

                runCatching { convertStringToX509Cert(pem) }.getOrNull()
            }
        val uniqueCerts = (certs + pemEncodeCerts).distinctBy {
            it.encoded.encodeToString(Base64 {})
        }

        println("Got ${certs.size} discrete certs and ${pemEncodeCerts.size} from trust store (${uniqueCerts.size} unique ones)")


        withData(nameFn = { it.subjectDN.name }, uniqueCerts.sortedBy { it.subjectDN.name }) { crt ->
            val own = X509Certificate.decodeFromTlv(Asn1Encodable.parse(crt.encoded) as Asn1Sequence)
                .encodeToTlv().derEncoded
            withClue(
                "Expect: ${crt.encoded.encodeToString(Base16)}\n" +
                        "Actual: ${own.encodeToString(Base16)}"
            ) {
                own shouldBe crt.encoded
            }
        }
    }

    "From Google's X509 Cert Test Suite" - {

        val (ok, faulty) = readGoogleCerts()

        "OK certs should parse" - {
            withData(nameFn = { it.first }, ok) {
                X509Certificate.decodeFromTlv(Asn1Encodable.parse(it.second) as Asn1Sequence)
            }
        }
        "Faulty certs should glitch out" - {
            withData(nameFn = { it.first }, faulty) {
               shouldThrow<Throwable> {
                   X509Certificate.decodeFromTlv(Asn1Encodable.parse(it.second) as Asn1Sequence)
               }
            }
        }


    }
})


private fun readGoogleCerts(): Pair<List<Pair<String, ByteArray>>, List<Pair<String, ByteArray>>> {
    val cert1 = File("./src/jvmTest/resources/certs").listFiles()
        .filter { it.extension == "der" && !it.name.contains(".chain.") }
    val certs2 =
        File("./src/jvmTest/resources/certs2").listFiles()
            .filter { it.extension == "der" && !it.name.contains(".chain.") }
    val all = cert1 + certs2

    val ok = all.filter { it.name.startsWith("ok-") }
    val faulty = all.filter { !it.name.startsWith("ok-") }
    return ok.map { it.name to it.readBytes() } to faulty.map { it.name to it.readBytes() }
}

@Throws(Exception::class)
private fun convertStringToX509Cert(certificate: String): java.security.cert.X509Certificate {
    val targetStream: InputStream = ByteArrayInputStream(certificate.toByteArray())
    return CertificateFactory
        .getInstance("X509")
        .generateCertificate(targetStream) as java.security.cert.X509Certificate
}