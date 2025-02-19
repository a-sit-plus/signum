package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.supreme.UnsupportedCryptoException
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.os.SignerConfiguration

actual class PlatformVerifierConfiguration internal actual constructor(): DSL.Data()

actual fun checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier(
    signatureAlgorithm: SignatureAlgorithm.RSA,
    publicKey: CryptoPublicKey.RSA,
    config: PlatformVerifierConfiguration
) {
    TODO("Not yet implemented")
}

actual fun verifyRSAImpl(
    signatureAlgorithm: SignatureAlgorithm.RSA,
    publicKey: CryptoPublicKey.RSA,
    data: SignatureInput,
    signature: CryptoSignature.RSAorHMAC,
    config: PlatformVerifierConfiguration
) {
    TODO("Not yet implemented")
}

actual fun checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier(
    signatureAlgorithm: SignatureAlgorithm.ECDSA,
    publicKey: CryptoPublicKey.EC,
    config: PlatformVerifierConfiguration
) {
    TODO("Not yet implemented")
}

actual fun verifyECDSAImpl(
    signatureAlgorithm: SignatureAlgorithm.ECDSA,
    publicKey: CryptoPublicKey.EC,
    data: SignatureInput,
    signature: CryptoSignature.EC,
    config: PlatformVerifierConfiguration
) {
    TODO("Not yet implemented")
}