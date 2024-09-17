package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.encoding.parseWithRemainder
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
import java.security.cert.X509Certificate as JcaCertificate


private val json = Json { prettyPrint = true }

class X509CertParserTest : FreeSpec({

    "Manual" {
        //ok-uniqueid-incomplete-byte.der
        val derBytes =
            javaClass.classLoader.getResourceAsStream("certs/ok-uniqueid-incomplete-byte.der").readBytes()
        X509Certificate.decodeFromDer(derBytes)

        val garbage = Random.nextBytes(Random.nextInt(0..128))
        Asn1Element.parseWithRemainder(derBytes + garbage).let { (parsed, remainder) ->
            parsed.derEncoded shouldBe derBytes
            remainder shouldBe garbage
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
                Asn1Element.parseWithRemainder(certBytes + garbage).let { (parsed, remainder) ->
                    parsed.derEncoded shouldBe certBytes
                    remainder shouldBe garbage
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
                Asn1Element.parseWithRemainder(crt.encoded + garbage).let { (parsed, remainder) ->
                    parsed.derEncoded shouldBe own
                    remainder shouldBe garbage
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
                Asn1Element.parseWithRemainder(it.second + garbage).let { (parsed, remainder) ->
                    parsed.derEncoded shouldBe it.second
                    remainder shouldBe garbage
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
                cert.encodeToTlv().derEncoded shouldBe encodedSrc

                val garbage = Random.nextBytes(Random.nextInt(0..128))
                Asn1Element.parseWithRemainder(jcaCert.encoded + garbage).let { (parsed, remainder) ->
                    parsed.derEncoded shouldBe jcaCert.encoded
                    remainder shouldBe garbage
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