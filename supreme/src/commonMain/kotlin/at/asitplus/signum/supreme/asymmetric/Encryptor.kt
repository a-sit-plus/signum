package at.asitplus.signum.supreme.asymmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.supreme.dsl.DSL


sealed interface Encryptor {
    val algorithm: AsymmetricEncryptionAlgorithm
    val publicKey: PublicKey

    fun encrypt(data: ByteArray): KmmResult<ByteArray>


    sealed class RSA(
        final override val algorithm: AsymmetricEncryptionAlgorithm.RSA,
        final override val publicKey: PublicKey.RSA
    ) : Encryptor
}


/** data is guaranteed to be in RAW_BYTES format. failure should throw. */
internal expect fun encryptRSAImpl(
    algorithm: AsymmetricEncryptionAlgorithm.RSA,
    publicKey: PublicKey.RSA,
    data: ByteArray,
    config: PlatformEncryptorConfiguration
): ByteArray

class PlatformRSAEncryptor
internal constructor(
    algorithm: AsymmetricEncryptionAlgorithm.RSA, publicKey: PublicKey.RSA,
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
    publicKey: PublicKey,
    config: ConfigurePlatformEncryptor = null
) = encryptorForImpl(publicKey, config)

private fun AsymmetricEncryptionAlgorithm.encryptorForImpl(
    publicKey: PublicKey,
    config: ConfigurePlatformEncryptor
): Encryptor =
    when (this) {
        is AsymmetricEncryptionAlgorithm.RSA -> PlatformRSAEncryptor(
            this,
            publicKey.let { require(it is PublicKey.RSA);it },
            config
        )
        else -> throw UnsupportedCryptoException("Unsupported asymmetric encryption algorithm $this")
    }

/**
 * Obtains an Encryptor.
 */
fun AsymmetricEncryptionAlgorithm.RSA.encryptorFor(
    publicKey: PublicKey.RSA,
    config: ConfigurePlatformEncryptor = null
) = encryptorForImpl(publicKey, config)
