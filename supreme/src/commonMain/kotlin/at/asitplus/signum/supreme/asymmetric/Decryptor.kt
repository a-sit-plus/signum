package at.asitplus.signum.supreme.asymmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.PrivateKey
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn


sealed interface Decryptor {
    val algorithm: AsymmetricEncryptionAlgorithm
    val privateKey: PrivateKey


    suspend fun decrypt(data: ByteArray): KmmResult<ByteArray>


    sealed class RSA(
        final override val algorithm: AsymmetricEncryptionAlgorithm.RSA,
        final override val privateKey: PrivateKey.RSA
    ) : Decryptor
}

expect class PlatformDecryptorConfiguration internal constructor() : DSL.Data
typealias ConfigurePlatformDecryptor = DSLConfigureFn<PlatformDecryptorConfiguration>
expect class PlatformEncryptorConfiguration internal constructor() : DSL.Data
typealias ConfigurePlatformEncryptor = DSLConfigureFn<PlatformEncryptorConfiguration>


/** data is guaranteed to be in RAW_BYTES format. failure should throw. */
internal expect suspend fun decryptRSAImpl(
    algorithm: AsymmetricEncryptionAlgorithm.RSA,
    privateKey: PrivateKey.RSA,
    data: ByteArray,
    config: PlatformDecryptorConfiguration
): ByteArray

class PlatformRSADecryptor
internal constructor(
    algorithm: AsymmetricEncryptionAlgorithm.RSA, privateKey: PrivateKey.RSA,
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
    privateKey: PrivateKey,
    configure: ConfigurePlatformDecryptor = null
) = decryptorForImpl(privateKey, configure)

private fun AsymmetricEncryptionAlgorithm.decryptorForImpl(
    privateKey: PrivateKey, configure: ConfigurePlatformDecryptor,
): Decryptor =
    when (this) {
        is AsymmetricEncryptionAlgorithm.RSA -> PlatformRSADecryptor(
            this,
            privateKey.let { require(it is PrivateKey.RSA);it },
            configure
        )
        else -> throw UnsupportedCryptoException("Unsupported asymmetric encryption algorithm $this")
    }
/**
 * Obtains a Decryptor.
 *
 * @see PlatformDecryptorConfiguration
 */
fun AsymmetricEncryptionAlgorithm.RSA.decryptorFor(
    privateKey: PrivateKey.RSA,
    configure: ConfigurePlatformDecryptor = null
) = decryptorForImpl(privateKey, configure)
