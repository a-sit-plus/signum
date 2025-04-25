package at.asitplus.signum.supreme.asymmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.asymmetric.RSAPadding
import at.asitplus.signum.supreme.sign.EphemeralKey
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.matthewnelson.encoding.base64.Base64
import kotlinx.io.bytestring.encode
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(HazardousMaterials::class, SecretExposure::class, ExperimentalStdlibApi::class, ExperimentalEncodingApi::class)
class `0000RsaEncrpytionTest` : FreeSpec({
    "Basic" - {
        val k = EphemeralKey {
            rsa {
                bits = 2048
            }
        }.getOrThrow()

        val pub = k.publicKey
        val data = "1337".encodeToByteArray()
        withData(RSAPadding.PKCS1, RSAPadding.NONE, RSAPadding.OAEP.SHA256) {
            println(k.exportPrivateKey().getOrThrow().encodeToPEM().getOrThrow())
            val encrypted = AsymmetricEncryptionAlgorithm.RSA(it).encryptorFor(pub).encrypt(data).getOrThrow()
            println(kotlin.io.encoding.Base64.encode(encrypted))
            println()
            println()
        }
    }
})