package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.supreme.os.SignerConfiguration

actual fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration): EphemeralKey {
    TODO("Not yet implemented")
}

actual fun makePrivateKeySigner(
    key: CryptoPrivateKey.EC.WithPublicKey,
    algorithm: SignatureAlgorithm.ECDSA
): Signer.ECDSA {
    TODO("Not yet implemented")
}

actual fun makePrivateKeySigner(
    key: CryptoPrivateKey.RSA,
    algorithm: SignatureAlgorithm.RSA
): Signer.RSA {
    TODO("Not yet implemented")
}

actual class EphemeralSigningKeyConfiguration internal actual constructor(): EphemeralSigningKeyConfigurationBase()

actual class EphemeralSignerConfiguration internal actual constructor(): SignerConfiguration()