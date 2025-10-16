package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.kotest.assertions.withClue
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.testSuite
import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldNotBeIn
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.io.UnsafeIoApi
import java.io.File
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

@OptIn(UnsafeIoApi::class)
val X509SignatureAlgorithmTest  by testSuite() {

    val (certsUnsupported, certsSupported) = readCerts()

    "OK certs with DSA signature algorithms, should parse" - {
        withData(nameFn = { it.first }, certsUnsupported) {
            val src = Asn1Element.parse(it.second) as Asn1Sequence
            val decoded = X509Certificate.decodeFromTlv(src)

            decoded.signatureAlgorithm.isSupported().shouldBeFalse()
            decoded.signatureAlgorithm shouldNotBeIn X509SignatureAlgorithm.entries

            //Certificate decoded successfully, but cryptographic operations on unsupported algorithms are not possible
             decoded.decodedSignature.isSuccess shouldBe false

            withClue(decoded.encodeToPEM().getOrNull()) {
                decoded.encodeToDer() shouldBe it.second
            }
        }
    }

    "OK certs with supported signature algorithms" - {
        withData(nameFn = { it.first }, certsSupported) {
            val src = Asn1Element.parse(it.second) as Asn1Sequence
            val decoded = X509Certificate.decodeFromTlv(src)
            decoded.signatureAlgorithm shouldBeIn X509SignatureAlgorithm.entries
            shouldNotThrow<Throwable> { decoded.decodedSignature }
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

