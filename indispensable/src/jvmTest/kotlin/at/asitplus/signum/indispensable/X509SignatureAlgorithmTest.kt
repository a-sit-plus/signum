package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.encoding.parse
import at.asitplus.signum.indispensable.encodeToPem
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.kotest.assertions.withClue
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldNotBeIn
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.io.UnsafeIoApi
import java.io.File
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny

@OptIn(UnsafeIoApi::class)
val X509SignatureAlgorithmTest  by testSuite {

    val (certsUnsupported, certsSupported) = readCerts()

    "OK certs with DSA signature algorithms, should parse" - {
        withData(nameFn = { it.first }, certsUnsupported) {
            val src = Asn1Element.parse(it.second) as Asn1Sequence
            val decoded = X509Certificate.decodeFromTlv(src)

            shouldThrowAny {

                decoded.signatureAlgorithm.toString()
            }


            withClue(decoded.encodeToPem()) {
                decoded.encodeToDer() shouldBe it.second
            }
        }
    }

    "OK certs with supported signature algorithms" - {
        withData(nameFn = { it.first }, certsSupported) {
            val src = Asn1Element.parse(it.second) as Asn1Sequence
            val decoded = X509Certificate.decodeFromTlv(src)
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
