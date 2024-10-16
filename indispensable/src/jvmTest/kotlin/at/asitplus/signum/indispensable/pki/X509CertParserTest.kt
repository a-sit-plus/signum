package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.encoding.parseFirst
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileReader
import java.io.InputStream
import java.security.cert.CertificateFactory
import java.util.*
import kotlin.random.Random
import kotlin.random.nextInt
import kotlin.text.HexFormat
import java.security.cert.X509Certificate as JcaCertificate

internal fun ByteIterator.toByteArray(): ByteArray =asSequence().toList().toByteArray()

private val json = Json { prettyPrint = true }

@OptIn(ExperimentalStdlibApi::class)
class X509CertParserTest : FreeSpec({

    "Manual" - {
        "ok-uniqueid-incomplete-byte.der" {
            val derBytes =
                javaClass.classLoader.getResourceAsStream("certs/ok-uniqueid-incomplete-byte.der").readBytes()
            X509Certificate.decodeFromDer(derBytes)

            val garbage = Random.nextBytes(Random.nextInt(0..128))
            val input = (derBytes + garbage)
            Asn1Element.parseFirst(input).let { parsed ->
                parsed.first.derEncoded shouldBe derBytes
                parsed.second shouldBe garbage
            }

        }
        "regression test" {
            val derBytes =
                "308201D53082015CA00302010202133D8CC3458C346EBD17871B13D1229C73074196300A06082A8648CE3D040303302931133011060355040A130A476F6F676C65204C4C43311230100603550403130944726F696420434132301E170D3233303531313138313335305A170D3233303631353138313334395A302931133011060355040A130A476F6F676C65204C4C43311230100603550403130944726F6964204341333059301306072A8648CE3D020106082A8648CE3D03010703420004AFF4215B16DA6C4D8C74088501B86B86AF42FFEE2354B2300233D0B00DCD9A4B0A3E9643B4FE892E0F587B8FC53F1B99385A9B07FACA4C19B5158437A73A8162A3633061300E0603551D0F0101FF040403020204300F0603551D130101FF040530030101FF301D0603551D0E04160414EB92862F31C3DB96A349FFCBA515642314B3D23D301F0603551D23041830168014BBF836AD89AE6CE2E59E94F0D5B2D7D27AE47C41300A06082A8648CE3D04030303670030640230077BEA0C7E5825232524FE131C71C6790D43DF087CCFCECAF8AED266431DDA3BA71F0CE02CFCBA6F11BCEC60777F01940230389756CA3F3965AD18AB416667F604E0EC9DA456AA97E21B9EE25F09B7A8039D018D639886FAE435D87BB2A3657EBF2B".hexToByteArray(
                    HexFormat.UpperCase
                )
            val cert = X509Certificate.decodeFromDer(derBytes)
            val jcaCert = CertificateFactory
                .getInstance("X509")
                .generateCertificate(ByteArrayInputStream(derBytes)) as java.security.cert.X509Certificate

            jcaCert.encoded shouldBe derBytes
            withClue("ACT: ${cert.encodeToTlv().toDerHexString()}\nEXP: ${derBytes.toHexString(HexFormat.UpperCase)}") {
                cert.encodeToTlv().derEncoded shouldBe derBytes
            }

        }
    }


    "Real Certificates" - {
        withData("digicert-root.pem", "github-com.pem", "cert-times.pem") { crt ->
            val certBytes = java.util.Base64.getMimeDecoder()
                .decode(javaClass.classLoader.getResourceAsStream(crt).reader().readText())
            val jcaCert = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(certBytes)) as JcaCertificate

            val cert = X509Certificate.decodeFromDer(certBytes)
            withClue(
                "Expect: ${jcaCert.encoded.encodeToString(Base16)}\n" +
                        "Actual: ${cert.encodeToDer().encodeToString(Base16)}"
            ) {
                cert.encodeToTlv().derEncoded shouldBe jcaCert.encoded

                cert shouldBe X509Certificate.decodeFromByteArray(certBytes)

                val garbage = Random.nextBytes(Random.nextInt(0..128))
                val input = (certBytes + garbage)
                Asn1Element.parseFirst(input).let { parsed ->
                    parsed.first.derEncoded shouldBe certBytes
                    parsed.second shouldBe garbage
                }
            }
        }
    }

    "system trust store" - {

        val certs = File("/etc/ssl/certs").listFiles { f: File -> f.name.endsWith(".pem") }?.mapNotNull {
            runCatching { convertStringToX509Cert(FileReader(it).readText()) }.getOrNull()
        } ?: emptyList()

        val macosCertsPem = kotlin.runCatching {
            Runtime.getRuntime().exec("security find-certificate -a -p").let {
                it.inputStream.reader().readText()
            }
        }.getOrNull()

        val pemEncodeCerts = runCatching {
            ((kotlin.runCatching {
                File("/etc/ssl/certs/ca-certificates.crt").readText().split(Regex.fromLiteral("-\n-"))
            }.getOrNull() ?: emptyList())
                    + (macosCertsPem?.split(Regex.fromLiteral("-\n-")) ?: emptyList())
                    )
                .mapNotNull {
                    var pem = if (it.startsWith("-----")) it else "-$it"
                    pem = if (!pem.endsWith("-----")) "$pem-" else pem

                    runCatching { convertStringToX509Cert(pem) }.getOrNull()
                }
        }.getOrElse {
            println("W: could not load System trust store")
            emptyList()
        }
        val uniqueCerts = (certs + pemEncodeCerts).distinctBy {
            it.encoded.encodeToString(Base64 {})
        }

        println("Got ${certs.size} discrete certs and ${pemEncodeCerts.size} from trust store (${uniqueCerts.size} unique ones)")

        withData(
            nameFn = {
                it.subjectX500Principal.name.let { name ->
                    if (name.isBlank() || name.isEmpty())
                        it.serialNumber.toString(16)
                    else name
                }
            },
            uniqueCerts.sortedBy { it.subjectX500Principal.name }) { crt ->
            val parsed = X509Certificate.decodeFromTlv(Asn1Element.parse(crt.encoded) as Asn1Sequence)
            val own = parsed.encodeToDer()
            withClue(
                "Expect: ${crt.encoded.encodeToString(Base16)}\n" + "Actual: ${own.encodeToString(Base16)}"
            ) {
                own shouldBe crt.encoded
                parsed shouldBe X509Certificate.decodeFromByteArray(crt.encoded)

                val garbage = Random.nextBytes(Random.nextInt(0..128))
                val bytes = (crt.encoded + garbage)
                Asn1Element.parseFirst(bytes).let { parsed ->
                    parsed.first.derEncoded shouldBe own
                    parsed.second shouldBe garbage
                }
            }
        }
    }

    "From Google's X509 Cert Test Suite" - {

        val (ok, faulty) = readGoogleCerts()

        "OK certs should parse" - {
            val good =
                ok.filterNot { it.first == "ok-inherited-keyparams.ca.der" || it.first == "ok-inherited-keyparams.leaf.der" } //filter out certs with DSA pubKeys

            withData(nameFn = { it.first }, good) {
                val src = Asn1Element.parse(it.second) as Asn1Sequence
                val decoded = X509Certificate.decodeFromTlv(src)
                decoded shouldBe X509Certificate.decodeFromByteArray(it.second)

                val garbage = Random.nextBytes(Random.nextInt(0..128))
                val bytes = (it.second + garbage)
                Asn1Element.parseFirst(bytes).let { parsed ->
                    parsed.first.derEncoded shouldBe it.second
                   parsed.second shouldBe garbage
                }
            }
        }
        "Faulty certs should glitch out" - {
            withData(nameFn = { it.first }, faulty) { crt ->
                runCatching {
                    shouldThrow<Throwable> {
                        X509Certificate.decodeFromTlv(Asn1Element.parse(crt.second) as Asn1Sequence)
                    }
                }.getOrElse { println("W: ${crt.first} parsed too leniently") }
            }
        }
    }



    "From attestation collector" - {
        val json = File("./src/jvmTest/resources/results").listFiles()
            ?.map { Pair(it.nameWithoutExtension, Json.parseToJsonElement(it.readText()).jsonObject) }
            .shouldNotBeNull()
        val certs = json.associate { (name, collected) ->
            (collected["device"]!!.jsonPrimitive.toString() + " ($name)") to collected.get("attestationProof")!!.jsonArray.map {
                it.jsonPrimitive.toString().replace("\\n", "").replace("\\r", "").replace("\"", "")
            }
        }

        withData(certs) {
            withData(it) {
                val encodedSrc = it.decodeToByteArray(Base64 {})

                val jcaCert = CertificateFactory
                    .getInstance("X509")
                    .generateCertificate(ByteArrayInputStream(encodedSrc)) as java.security.cert.X509Certificate

                val cert = X509Certificate.decodeFromDer(encodedSrc)

                jcaCert.encoded shouldBe encodedSrc
                withClue("ACT: ${cert.encodeToTlv().toDerHexString()}\nEXP: ${encodedSrc.toHexString(HexFormat.UpperCase)}") {
                    cert.encodeToTlv().derEncoded shouldBe encodedSrc
                }

                val garbage = Random.nextBytes(Random.nextInt(0..128))
                val input = (jcaCert.encoded + garbage)
                Asn1Element.parseFirst(input).let { parsed ->
                    parsed.first.derEncoded shouldBe jcaCert.encoded
                    parsed.second shouldBe garbage
                }
            }
        }

    }

})


private fun readGoogleCerts(): Pair<List<Pair<String, ByteArray>>, List<Pair<String, ByteArray>>> {
    val cert1 = File("./src/jvmTest/resources/certs").listFiles()
        ?.filter { it.extension == "der" && !it.name.contains(".chain.") }
        .shouldNotBeNull()
    val certs2 = File("./src/jvmTest/resources/certs2").listFiles()
        ?.filter { it.extension == "der" && !it.name.contains(".chain.") }
        .shouldNotBeNull()
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