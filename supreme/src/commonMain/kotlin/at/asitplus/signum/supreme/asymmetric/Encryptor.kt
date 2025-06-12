package at.asitplus.signum.supreme.asymmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.supreme.dsl.DSL


sealed interface Encryptor {
    val algorithm: AsymmetricEncryptionAlgorithm
    val publicKey: CryptoPublicKey

    fun encrypt(data: ByteArray): KmmResult<ByteArray>


    sealed class RSA(
        final override val algorithm: AsymmetricEncryptionAlgorithm.RSA,
        final override val publicKey: CryptoPublicKey.RSA
    ) : Encryptor
}


/** data is guaranteed to be in RAW_BYTES format. failure should throw. */
internal expect fun encryptRSAImpl(
    algorithm: AsymmetricEncryptionAlgorithm.RSA,
    publicKey: CryptoPublicKey.RSA,
    data: ByteArray,
    config: PlatformEncryptorConfiguration
): ByteArray

class PlatformRSAEncryptor
internal constructor(
    algorithm: AsymmetricEncryptionAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
    configure: ConfigurePlatformEncryptor
) : Encryptor.RSA(algorithm, publicKey) {

    private val config = DSL.resolve(::PlatformEncryptorConfiguration, configure)

    override fun encrypt(data: ByteArray) = catching {
        require(data.size.toUInt() * 8u <= publicKey.n.bitLength())
        encryptRSAImpl(algorithm, publicKey, data, config)
    }
}

/**
 * Obtains an Encryptor.
 */
fun AsymmetricEncryptionAlgorithm.encryptorFor(
    publicKey: CryptoPublicKey,
    config: ConfigurePlatformEncryptor = null
) = encryptorForImpl(publicKey, config)

private fun AsymmetricEncryptionAlgorithm.encryptorForImpl(
    publicKey: CryptoPublicKey,
    config: ConfigurePlatformEncryptor
): Encryptor =
    when (this) {
        is AsymmetricEncryptionAlgorithm.RSA -> PlatformRSAEncryptor(
            this,
            publicKey.let { require(it is CryptoPublicKey.RSA);it },
            config
        )
    }

/**
 * Obtains an Encryptor.
 */
fun AsymmetricEncryptionAlgorithm.RSA.encryptorFor(
    publicKey: CryptoPublicKey.RSA,
    config: ConfigurePlatformEncryptor = null
) = encryptorForImpl(publicKey, config)