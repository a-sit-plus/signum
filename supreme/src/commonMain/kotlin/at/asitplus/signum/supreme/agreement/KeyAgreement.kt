package at.asitplus.signum.supreme.agreement

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.curve
import at.asitplus.signum.supreme.sign.signerFor

/**
 * Elliptic-curve Diffie-Hellman key agreement.
 * Curves of public key and signer need to match!
 */
fun Signer.ECDSA.keyAgreement(publicKey: CryptoPublicKey.EC): KmmResult<ByteArray> = catching {
    require(curve == publicKey.curve) { "Private and public key curve mismatch" }
    performAgreement(publicKey)
}

/**
 * Elliptic-curve Diffie-Hellman key agreement.
 * Curves of public key and signer need to match!
 */
fun CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC>.keyAgreement(publicKey: CryptoPublicKey.EC) = catching {
    (SignatureAlgorithm.ECDSA(this.publicKey.curve.nativeDigest, this.publicKey.curve).signerFor(this)
        .getOrThrow() as Signer.ECDSA).keyAgreement(
        publicKey
    )
}

/**
 * Elliptic-curve Diffie-Hellman key agreement.
 * Curves of public key and signer need to match!
 */
fun CryptoPublicKey.EC.keyAgreement(privateKey: CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC>) = privateKey.keyAgreement(this)

/**
 * Elliptic-curve Diffie-Hellman key agreement.
 * Curves of public key and signer need to match!
 */
fun CryptoPublicKey.EC.keyAgreement(signer: Signer.ECDSA) = signer.keyAgreement(this)

//TODO CFG lambda for auth dialog, etc
internal expect fun Signer.ECDSA.performAgreement(publicKey: CryptoPublicKey.EC): ByteArray