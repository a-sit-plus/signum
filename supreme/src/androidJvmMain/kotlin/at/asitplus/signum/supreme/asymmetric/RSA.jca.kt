package at.asitplus.signum.supreme.asymmetric

import at.asitplus.signum.indispensable.PrivateKey
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.getJCADecryptorInstance
import at.asitplus.signum.indispensable.getJCAEncryptorInstance
import at.asitplus.signum.supreme.dsl.DSL

actual class PlatformDecryptorConfiguration internal actual constructor() :
    DSL.Data() {
    var provider: String? = null
    //TODO provider config like biometrics, once we support HW-backed storage
}


actual class PlatformEncryptorConfiguration internal actual constructor() :
    DSL.Data() {
    var provider: String? = null
}


/** data is guaranteed to be in RAW_BYTES format. failure should throw. */
internal actual fun encryptRSAImpl(
    algorithm: AsymmetricEncryptionAlgorithm.RSA,
    publicKey: PublicKey.RSA,
    data: ByteArray,
    config: PlatformEncryptorConfiguration
): ByteArray = algorithm.getJCAEncryptorInstance(publicKey, config.provider).getOrThrow().run {
    doFinal(data)
}

internal actual suspend fun decryptRSAImpl(
    algorithm: AsymmetricEncryptionAlgorithm.RSA,
    privateKey: PrivateKey.RSA,
    data: ByteArray,
    config: PlatformDecryptorConfiguration
): ByteArray =
    algorithm.getJCADecryptorInstance(
        privateKey,
        config.provider /*TODO provider config like biometrics, once we support HW-backed storage*/
    ).getOrThrow().run {
        doFinal(data)
    }
