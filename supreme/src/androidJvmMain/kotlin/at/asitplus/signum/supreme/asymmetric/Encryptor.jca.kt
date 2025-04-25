package at.asitplus.signum.supreme.asymmetric

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.supreme.dsl.DSL
import javax.crypto.Cipher

actual class PlatformEncryptorConfiguration internal actual constructor() : DSL.Data() //TODO provider


/** data is guaranteed to be in RAW_BYTES format. failure should throw. */
internal actual fun encryptRSAImpl(
    algorithm: AsymmetricEncryptionAlgorithm.RSA,
    publicKey: CryptoPublicKey.RSA,
    data: ByteArray,
    config: PlatformEncryptorConfiguration
): ByteArray = Cipher.getInstance("RSA/ECB/PKCS1Padding").run {
    init(Cipher.ENCRYPT_MODE, publicKey.toJcaPublicKey().getOrThrow())
    doFinal()
}
