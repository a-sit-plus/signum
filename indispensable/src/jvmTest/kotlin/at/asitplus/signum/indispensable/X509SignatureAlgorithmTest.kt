package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.encoding.parse
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.io.UnsafeIoApi
import java.io.File
import io.kotest.assertions.throwables.shouldThrowAny

@OptIn(UnsafeIoApi::class)
val X509SignatureAlgorithmTest by matrixSuite {

    val (certsUnsupported, certsSupported) = readCerts()

    compact("!OK certs with DSA signature algorithms, should parse") - {
        data(certsUnsupported, nameFn = { it.first }) test {
            val src = Asn1Element.parse(it.second) as Asn1Sequence
            val decoded = Certificate.decodeFromTlv(src)

            shouldThrowAny {

                decoded.signatureAlgorithm.toString()
            }


            withClue(decoded.encodeToPem()) {
                decoded.encodeToDer() shouldBe it.second
            }
        }
    }

    compact("OK certs with supported signature algorithms") - {
        data(certsSupported, nameFn = { it.first }) test {
            val src = Asn1Element.parse(it.second) as Asn1Sequence
            val decoded = Certificate.decodeFromTlv(src)
            decoded.signatureAlgorithm shouldBeIn SignatureAlgorithm.entries.toList()
            shouldNotThrow<Throwable> { decoded.signature.toString() }
        }
    }


}

private fun readCerts(): Pair<List<Pair<String, ByteArray>>, List<Pair<String, ByteArray>>> {
    val certsUnsupported = File("./src/jvmTest/resources/certs-DSA").listFiles().shouldNotBeNull()
    val cert1 = File("./src/jvmTest/resources/certs").listFiles()
        ?.filter { it.extension == "der" && !it.name.contains(".chain.") }
        .shouldNotBeNull()

    val certsSupported = cert1.filter { it.name.startsWith("ok-") }
    return certsUnsupported.map { it.name to it.readBytes() } to certsSupported.map { it.name to it.readBytes() }
}
