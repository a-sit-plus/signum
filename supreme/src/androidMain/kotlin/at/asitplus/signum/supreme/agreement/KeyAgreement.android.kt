package at.asitplus.signum.supreme.agreement

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.hazmat.jcaPrivateKey
import at.asitplus.signum.supreme.sign.Signer
import javax.crypto.KeyAgreement

actual fun Signer.ECDSA.performAgreement(publicKey: CryptoPublicKey.EC): ByteArray =
    javax.crypto.KeyAgreement.getInstance("ECDH").also {
        @OptIn(HazardousMaterials::class)
        it.init(jcaPrivateKey)
        it.doPhase(publicKey.toJcaPublicKey().getOrThrow(), true)
    }.generateSecret()
