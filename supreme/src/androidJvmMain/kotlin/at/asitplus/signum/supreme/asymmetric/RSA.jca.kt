package at.asitplus.signum.supreme.asymmetric

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.jcaName
import at.asitplus.signum.indispensable.toJcaPrivateKey
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.supreme.dsl.DSL
import javax.crypto.Cipher

actual class PlatformDecryptorConfiguration internal actual constructor() : DSL.Data() //TODO provider config like biometrics


/** data is guaranteed to be in RAW_BYTES format. failure should throw. */
internal actual fun encryptRSAImpl(
    algorithm: AsymmetricEncryptionAlgorithm.RSA,
    publicKey: CryptoPublicKey.RSA,
    data: ByteArray,
): ByteArray = Cipher.getInstance(algorithm.jcaName).run {
    init(Cipher.ENCRYPT_MODE, publicKey.toJcaPublicKey().getOrThrow())
    doFinal()
}

internal actual suspend fun decryptRSAImpl(
    algorithm: AsymmetricEncryptionAlgorithm.RSA,
    privateKey: CryptoPrivateKey.RSA,
    data: ByteArray,
    config: PlatformDecryptorConfiguration
): ByteArray  = Cipher.getInstance(algorithm.jcaName).run {
    init(Cipher.DECRYPT_MODE, privateKey.toJcaPrivateKey().getOrThrow())
    doFinal()
}
