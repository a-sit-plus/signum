import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.cose.CoseAlgorithm
import at.asitplus.crypto.datatypes.cose.toCoseAlgorithm
import at.asitplus.crypto.datatypes.toX509SignatureAlgorithm
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe

infix fun <T> KmmResult<T>.shouldSucceedWith(b: T) : T =
    (this.getOrThrow() shouldBe b)

class ConversionTests : FreeSpec({
    "COSE -> SigAlg -> COSE is stable" - {
        withData(CoseAlgorithm.entries) {
            it.toCoseAlgorithm() shouldSucceedWith  it
            it.algorithm.toCoseAlgorithm() shouldSucceedWith it
        }
    }
    "COSE -> X509 -> COSE is stable" - {
        withData(CoseAlgorithm.entries) {
            it.toX509SignatureAlgorithm().getOrNull()?.let { x509 ->
                x509.toCoseAlgorithm() shouldSucceedWith it
            }
        }
    }
})
