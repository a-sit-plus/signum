package at.asitplus.signum.supreme.agreement

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.curve

fun Signer.ECDSA.keyAgreement(publicKey: CryptoPublicKey.EC): KmmResult<ByteArray> = catching {
    require(curve == publicKey.curve) {"Private and public key curve mismatch"}
    performAgreement(publicKey)
}
//TODO CFG lambda for auth dialog, etc
internal expect fun Signer.ECDSA.performAgreement(publicKey: CryptoPublicKey.EC): ByteArray