package at.asitplus.signum.supreme.asymmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.sign.RSAPrivateKey
import at.asitplus.signum.dsl.DSL
import at.asitplus.signum.dsl.DSLConfigureFn


sealed interface Decryptor {
    val algorithm: AsymmetricEncryptionAlgorithm
    val privateKey: CryptoPrivateKey


    suspend fun decrypt(data: ByteArray): KmmResult<ByteArray>


    sealed class RSA(
        final override val algorithm: AsymmetricEncryptionAlgorithm.RSA,
        final override val privateKey: at.asitplus.signum.indispensable.sign.RSAPrivateKey
    ) : Decryptor
}

expect class PlatformDecryptorConfiguration internal constructor() : DSL.Data
typealias ConfigurePlatformDecryptor = DSLConfigureFn<PlatformDecryptorConfiguration>
expect class PlatformEncryptorConfiguration internal constructor() : DSL.Data
typealias ConfigurePlatformEncryptor = DSLConfigureFn<PlatformEncryptorConfiguration>


/** data is guaranteed to be in RAW_BYTES format. failure should throw. */
internal expect suspend fun decryptRSAImpl(
    algorithm: AsymmetricEncryptionAlgorithm.RSA,
    privateKey: RSAPrivateKey,
    data: ByteArray,
    config: PlatformDecryptorConfiguration
): ByteArray

class PlatformRSADecryptor
internal constructor(
    algorithm: AsymmetricEncryptionAlgorithm.RSA, privateKey: RSAPrivateKey,
    configure: ConfigurePlatformDecryptor
) : Decryptor.RSA(algorithm, privateKey) {

    private val config = DSL.resolve(::PlatformDecryptorConfiguration, configure)


    override suspend fun decrypt(data: ByteArray) = catching {
        require(data.size.toUInt() * 8u <= privateKey.publicKey.n.bitLength())
        decryptRSAImpl(algorithm, privateKey, data, config)
    }
}

/**
 * Obtains a Decryptor.
 *
 * @see PlatformDecryptorConfiguration
 */
fun AsymmetricEncryptionAlgorithm.decryptorFor(
    privateKey: CryptoPrivateKey,
    configure: ConfigurePlatformDecryptor = null
) = decryptorForImpl(privateKey, configure)

private fun AsymmetricEncryptionAlgorithm.decryptorForImpl(
    privateKey: CryptoPrivateKey, configure: ConfigurePlatformDecryptor,
): Decryptor =
    when (this) {
        is AsymmetricEncryptionAlgorithm.RSA -> PlatformRSADecryptor(
            this,
            privateKey.let { require(it is RSAPrivateKey);it },
            configure
        )
    }
/**
 * Obtains a Decryptor.
 *
 * @see PlatformDecryptorConfiguration
 */
fun AsymmetricEncryptionAlgorithm.RSA.decryptorFor(
    privateKey: RSAPrivateKey,
    configure: ConfigurePlatformDecryptor = null
) = decryptorForImpl(privateKey, configure)