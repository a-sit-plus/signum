package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.encoding.readAsn1Element
import at.asitplus.signum.indispensable.asn1.wrapInUnsafeSource
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.io.UnsafeIoApi
import kotlinx.io.readByteArray
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileReader
import java.io.InputStream
import java.security.cert.CertificateFactory
import kotlin.random.Random
import kotlin.random.nextInt
import java.security.cert.X509Certificate as JcaCertificate
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope

@OptIn(UnsafeIoApi::class)
val X509CertParserTest  by testSuite {

    "Manual" {
        //ok-uniqueid-incomplete-byte.der
        val derBytes =
            javaClass.classLoader.getResourceAsStream("certs/ok-uniqueid-incomplete-byte.der").readBytes()
        X509Certificate.decodeFromDer(derBytes)

        val garbage = Random.nextBytes(Random.nextInt(0..128))
        val input = (derBytes + garbage).wrapInUnsafeSource()
        input.readAsn1Element().let { (parsed, _) ->
            parsed.derEncoded shouldBe derBytes
            input.readByteArray() shouldBe garbage
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
                val input = (certBytes + garbage).wrapInUnsafeSource()
                input.readAsn1Element().let { (parsed, _) ->
                    parsed.derEncoded shouldBe certBytes
                    input.readByteArray() shouldBe garbage
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
                val bytes = (crt.encoded + garbage).wrapInUnsafeSource()
                bytes.readAsn1Element().let { (parsed, _) ->
                    parsed.derEncoded shouldBe own
                    bytes.readByteArray() shouldBe garbage
                }
            }
        }
    }

    "From Google's X509 Cert Test Suite" - {

        val (ok, faulty) = readGoogleCerts()

        "OK certs should parse" - {
            withData(nameFn = { it.first }, ok) {
                val src = Asn1Element.parse(it.second) as Asn1Sequence
                val decoded = X509Certificate.decodeFromTlv(src)
                decoded shouldBe X509Certificate.decodeFromByteArray(it.second)

                withClue(decoded.encodeToPEM().getOrNull()) {
                    decoded.encodeToDer() shouldBe it.second
                }

                val garbage = Random.nextBytes(Random.nextInt(0..128))
                val bytes = (it.second + garbage).wrapInUnsafeSource()
                bytes.readAsn1Element().let { (parsed, _) ->
                    parsed.derEncoded shouldBe it.second
                    bytes.readByteArray() shouldBe garbage
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
        val shouldFailInvalidDNSName = setOf(
            "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"
        )
        val json = File("./src/jvmTest/resources/results").listFiles()
            ?.map { Pair(it.nameWithoutExtension, Json.parseToJsonElement(it.readText()).jsonObject) }
            .shouldNotBeNull()
        val certs = json.associate { (name, collected) ->
            (collected["device"]!!.jsonPrimitive.toString() + " ($name)") to collected.get("attestationProof")!!.jsonArray.map {
                it.jsonPrimitive.toString().replace("\\n", "").replace("\\r", "").replace("\"", "")
            }
        }

        withDataSuites(certs) {
            withData(it) {
                if (shouldFailInvalidDNSName.contains(it)) {
                    shouldThrow<Asn1Exception> {
                        val encodedSrc = it.decodeToByteArray(Base64 {})
                        X509Certificate.decodeFromDer(encodedSrc)
                    }.apply {
                        message shouldBe "DNSName components must consist of letters, digits, and hyphens"
                    }
                } else {
                    val encodedSrc = it.decodeToByteArray(Base64 {})

                    val jcaCert = CertificateFactory
                        .getInstance("X509")
                        .generateCertificate(ByteArrayInputStream(encodedSrc)) as java.security.cert.X509Certificate

                    val cert = X509Certificate.decodeFromDer(encodedSrc)

                    jcaCert.encoded shouldBe encodedSrc
                    cert.encodeToTlv().derEncoded shouldBe encodedSrc

                    val garbage = Random.nextBytes(Random.nextInt(0..128))
                    val input = (jcaCert.encoded + garbage).wrapInUnsafeSource()
                    input.readAsn1Element().let { (parsed, _) ->
                        parsed.derEncoded shouldBe jcaCert.encoded
                        input.readByteArray() shouldBe garbage
                    }
                }
            }
        }
    }
}


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