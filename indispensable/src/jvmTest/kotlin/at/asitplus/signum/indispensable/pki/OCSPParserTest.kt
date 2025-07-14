package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.encoding.readAsn1Element
import at.asitplus.signum.indispensable.asn1.wrapInUnsafeSource
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.io.UnsafeIoApi
import kotlinx.io.readByteArray
import java.io.File
import kotlin.random.Random
import kotlin.random.nextInt

@OptIn(UnsafeIoApi::class)
class OCSPParserTest : FreeSpec({
    val (ok, faulty) = readOCSPRequests()

    "OK OCSP requests should parse" - {
        withData(nameFn = { it.first }, ok) {
            val src = Asn1Element.parse(it.second).asSequence()
            val decoded = OCSPRequest.decodeFromTlv(src)
            decoded shouldBe OCSPRequest.decodeFromByteArray(it.second)

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

    "Faulty OCSP requests should glitch out" - {
        withData(nameFn = { it.first }, faulty) { crt ->
            runCatching {
                shouldThrow<Throwable> {
                    OCSPRequest.decodeFromTlv(Asn1Element.parse(crt.second).asSequence())
                }
            }.getOrElse { println("W: ${crt.first} parsed too leniently") }
        }
    }
})


private fun readOCSPRequests(): Pair<List<Pair<String, ByteArray>>, List<Pair<String, ByteArray>>> {
    val requests = File("./src/jvmTest/resources/ocsp").listFiles()
        ?.filter { it.extension == "der" }
        .shouldNotBeNull()
    val ok = requests.filterNot { it.name.equals("req-duplicate-ext.der") }
    val faulty = requests.filter { it.name.equals("req-duplicate-ext.der") }
    return ok.map { it.name to it.readBytes() } to faulty.map { it.name to it.readBytes() }
}