package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.encoding.readAsn1Element
import at.asitplus.signum.indispensable.asn1.wrapInUnsafeSource
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.io.UnsafeIoApi
import kotlinx.io.readByteArray
import java.io.File
import kotlin.random.Random
import kotlin.random.nextInt
import at.asitplus.testballoon.invoke


@OptIn(UnsafeIoApi::class)
val OCSPParserTest by testSuite{
    val (reqOk, reqFaulty) = readOCSP("./src/jvmTest/resources/ocsp/requests", "./src/jvmTest/resources/ocsp/faulty_requests")
    val (respOk, respFaulty) = readOCSP("./src/jvmTest/resources/ocsp/responses", "./src/jvmTest/resources/ocsp/faulty_responses")

    context("OK OCSP requests should parse") {
        reqOk.forEach { (name, bytes) ->
            test("OK OCSP requests: $name") {
                val src = Asn1Element.parse(bytes).asSequence()
                val decoded = OCSPRequest.decodeFromTlv(src)
                decoded shouldBe OCSPRequest.decodeFromByteArray(bytes)

                withClue(decoded.encodeToPEM().getOrNull()) {
                    decoded.encodeToDer() shouldBe bytes
                }

                val garbage = Random.nextBytes(Random.nextInt(0..128))
                val garBytes = (bytes + garbage).wrapInUnsafeSource()
                garBytes.readAsn1Element().let { (parsed, _) ->
                    parsed.derEncoded shouldBe bytes
                    garBytes.readByteArray() shouldBe garbage
                }
            }
        }
    }

    context("Faulty OCSP requests should glitch out") {
        reqFaulty.forEach { (name, bytes) ->
            test("Faulty OCSP requests: $name") {
                shouldThrow<Throwable> {
                    OCSPRequest.decodeFromTlv(
                        Asn1Element.parse(bytes).asSequence()
                    )
                }
            }
        }
    }


    context("OK OCSP responses should parse") {
        respOk.forEach { (name, bytes) ->
            test("OK OCSP responses: $name") {
                val src = Asn1Element.parse(bytes).asSequence()
                val decoded = OCSPResponse.decodeFromTlv(src)
                decoded shouldBe OCSPResponse.decodeFromByteArray(bytes)

                withClue(decoded.encodeToPEM().getOrNull()) {
                    decoded.encodeToDer() shouldBe bytes
                }

                val garbage = Random.nextBytes(Random.nextInt(0..128))
                val garBytes = (bytes + garbage).wrapInUnsafeSource()
                garBytes.readAsn1Element().let { (parsed, _) ->
                    parsed.derEncoded shouldBe bytes
                    garBytes.readByteArray() shouldBe garbage
                }
            }
        }
    }

    context("Faulty OCSP responses should glitch out") {
        respFaulty.forEach { (name, bytes) ->
            test("Faulty OCSP responses: $name") {
                runCatching {
                    shouldThrow<Throwable> {
                        OCSPRequest.decodeFromTlv(Asn1Element.parse(bytes).asSequence())
                    }
                }.getOrElse { println("W: $name parsed too leniently") }
            }
        }
    }
}

private fun readOCSP(pathOk: String, pathFaulty: String): Pair<List<Pair<String, ByteArray>>, List<Pair<String, ByteArray>>> {
    val ok = File(pathOk).listFiles().shouldNotBeNull()
    val faulty = File(pathFaulty).listFiles().shouldNotBeNull()
    return ok.map { it.name to it.readBytes() } to faulty.map { it.name to it.readBytes() }
}