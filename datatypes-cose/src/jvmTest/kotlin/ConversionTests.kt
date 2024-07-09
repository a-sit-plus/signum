import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.X509SignatureAlgorithm
import at.asitplus.crypto.datatypes.asn1.Asn1String
import at.asitplus.crypto.datatypes.asn1.Asn1Time
import at.asitplus.crypto.datatypes.cose.CoseAlgorithm
import at.asitplus.crypto.datatypes.cose.toCoseAlgorithm
import at.asitplus.crypto.datatypes.cose.toCoseKey
import at.asitplus.crypto.datatypes.fromJcaPublicKey
import at.asitplus.crypto.datatypes.pki.AttributeTypeAndValue
import at.asitplus.crypto.datatypes.pki.RelativeDistinguishedName
import at.asitplus.crypto.datatypes.pki.TbsCertificate
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.crypto.datatypes.toX509SignatureAlgorithm
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import kotlinx.datetime.Clock
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import kotlin.random.Random

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
