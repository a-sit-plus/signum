import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.fromJcaPublicKey
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import kotlin.random.Random

infix fun <T> KmmResult<T>.shouldSucceedWith(b: T) : T =
    (this.getOrThrow() shouldBe b)

class ConversionTests : FreeSpec({
    "COSE -> SigAlg -> COSE is stable" - {

        "All" - {
            withData(CoseAlgorithm.DataIntegrity.entries) {
                it.algorithm.toCoseAlgorithm() shouldSucceedWith it
            }
        }
        "Specialized Signature Algorithms" - {
            withData(CoseAlgorithm.Signature.entries) {
                it.toCoseAlgorithm() shouldSucceedWith it
            }
        }
    }
    "COSE -> X509 -> COSE is stable" - {
        withData(CoseAlgorithm.Signature.entries) {
            it.toX509SignatureAlgorithm().getOrNull()?.let { x509 ->
                x509.toCoseAlgorithm() shouldSucceedWith it
            }
        }
    }

    "Regression test: COSE key (no keyId) -> CryptoPublicKey -> COSE key (no keyId)" {
        val key = randomPublicKey().toCoseKey().getOrThrow()
        key.keyId shouldBe null
        val cpk = key.toCryptoPublicKey().getOrThrow()
        cpk.toCoseKey().getOrThrow().keyId shouldBe null
        val kid = Random.nextBytes(16)
        cpk.toCoseKey(keyId = kid).getOrThrow().keyId shouldBe kid
    }
})

private fun randomPublicKey() =
    CryptoPublicKey.EC.fromJcaPublicKey(KeyPairGenerator.getInstance("EC").apply { initialize(256) }
        .genKeyPair().public as ECPublicKey).getOrThrow()
