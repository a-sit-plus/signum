package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.encoding.readAsn1Element
import at.asitplus.signum.indispensable.asn1.wrapInUnsafeSource
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
class X509CRLParserTest : FreeSpec({
    val crls = readPKITScrls().filterNot { it.first == "DSACACRL.crl" || it.first == "DSAParametersInheritedCACRL.crl" } //filter out CRLs with DSA pubKeys

    "PKITS CRLs, should parse" - {
        withData(nameFn = { it.first }, crls) {
            val src = Asn1Element.parse(it.second) as Asn1Sequence
            val decoded = CertificateList.decodeFromTlv(src)
            decoded shouldBe CertificateList.decodeFromByteArray(it.second)

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
})

private fun readPKITScrls(): List<Pair<String, ByteArray>> {
    val crls = File("./src/jvmTest/resources/crls/PKITS_crl").listFiles()
        ?.filter { it.extension == "crl" }
        .shouldNotBeNull()

    return crls.map { it.name to it.readBytes() }
}