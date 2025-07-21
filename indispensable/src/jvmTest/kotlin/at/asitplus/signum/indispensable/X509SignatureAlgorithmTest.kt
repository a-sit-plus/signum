package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.kotest.assertions.withClue
import at.asitplus.test.FreeSpec
import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.datatest.withData
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldNotBeIn
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.io.UnsafeIoApi
import java.io.File

@OptIn(UnsafeIoApi::class)
class X509SignatureAlgorithmTest : FreeSpec({

    val (certsUnsupported, certsSupported) = readCerts()

    "OK certs with DSA signature algorithms, should parse" - {
        withData(nameFn = { it.first }, certsUnsupported) {
            val src = Asn1Element.parse(it.second) as Asn1Sequence
            val decoded = X509Certificate.decodeFromTlv(src)

            decoded.signatureAlgorithm.isSupported().shouldBeFalse()
            decoded.signatureAlgorithm shouldNotBeIn X509SignatureAlgorithm.Supported.entries

            //Certificate decoded successfully, but cryptographic operations on unsupported algorithms are not possible
             decoded.decodedSignature.shouldBeNull()

            withClue(decoded.encodeToPEM().getOrNull()) {
                decoded.encodeToDer() shouldBe it.second
            }
        }
    }

    "OK certs with supported signature algorithms" - {
        withData(nameFn = { it.first }, certsSupported) {
            val src = Asn1Element.parse(it.second) as Asn1Sequence
            val decoded = X509Certificate.decodeFromTlv(src)
            decoded.signatureAlgorithm shouldBeIn X509SignatureAlgorithm.Supported.entries
            shouldNotThrow<Throwable> { decoded.decodedSignature }
        }
    }



})

private fun readCerts(): Pair<List<Pair<String, ByteArray>>, List<Pair<String, ByteArray>>> {
    val certsUnsupported = File("./src/jvmTest/resources/certs-DSA").listFiles().shouldNotBeNull()
    val cert1 = File("./src/jvmTest/resources/certs").listFiles()
        ?.filter { it.extension == "der" && !it.name.contains(".chain.") }
        .shouldNotBeNull()

    val certsSupported = cert1.filter { it.name.startsWith("ok-") }
    return certsUnsupported.map { it.name to it.readBytes() } to certsSupported.map { it.name to it.readBytes() }
}

