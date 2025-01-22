package at.asitplus.signum.supreme.agreement

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.supreme.sign.signerFor

suspend fun CryptoPrivateKey.EC.WithPublicKey.keyAgreement(publicKey: CryptoPublicKey) =
    SignatureAlgorithm.ECDSA(curve.nativeDigest, null)
        .signerFor(this)
        .mapCatching { it.keyAgreement(publicKey) }
