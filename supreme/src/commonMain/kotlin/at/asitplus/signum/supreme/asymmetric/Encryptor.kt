package at.asitplus.signum.supreme.asymmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.asymmetric.RsaEncryptionAlgorithm
import at.asitplus.signum.indispensable.key.RsaPublicKey
import at.asitplus.signum.supreme.dsl.DSL


sealed interface Encryptor {
    val algorithm: AsymmetricEncryptionAlgorithm
    val publicKey: at.asitplus.signum.indispensable.key.PublicKey

    fun encrypt(data: ByteArray): KmmResult<ByteArray>


    sealed class RSA(
        final override val algorithm: RsaEncryptionAlgorithm,
        final override val publicKey: RsaPublicKey
    ) : Encryptor
}


/** data is guaranteed to be in RAW_BYTES format. failure should throw. */
internal expect fun encryptRSAImpl(
    algorithm: RsaEncryptionAlgorithm,
    publicKey: RsaPublicKey,
    data: ByteArray,
    config: PlatformEncryptorConfiguration
): ByteArray

class PlatformRSAEncryptor
internal constructor(
    algorithm: RsaEncryptionAlgorithm, publicKey: RsaPublicKey,
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
        is RsaEncryptionAlgorithm -> PlatformRSAEncryptor(
            this,
            publicKey.let { require(it is RsaPublicKey);it },
            config
        )
        else -> throw UnsupportedCryptoException("Unsupported asymmetric encryption algorithm $this")
    }

/**
 * Obtains an Encryptor.
 */
fun RsaEncryptionAlgorithm.encryptorFor(
    publicKey: RsaPublicKey,
    config: ConfigurePlatformEncryptor = null
) = encryptorForImpl(publicKey, config)
