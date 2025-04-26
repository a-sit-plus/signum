package at.asitplus.signum.supreme.asymmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm


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
): ByteArray

class PlatformRSAEncryptor
internal constructor(
    algorithm: AsymmetricEncryptionAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
) : Encryptor.RSA(algorithm, publicKey) {



    override fun encrypt(data: ByteArray) = catching {
        require(data.size.toUInt() * 8u <= publicKey.n.bitLength())
        encryptRSAImpl(algorithm, publicKey, data)
    }
}

/**
 * Obtains an Encryptor.
 *
 * @see PlatformDecryptorConfiguration
 */
fun AsymmetricEncryptionAlgorithm.encryptorFor(
    publicKey: CryptoPublicKey,
) = encryptorForImpl(publicKey)

private fun AsymmetricEncryptionAlgorithm.encryptorForImpl(
    publicKey: CryptoPublicKey
): Encryptor =
    when (this) {
        is AsymmetricEncryptionAlgorithm.RSA -> PlatformRSAEncryptor(
            this,
            publicKey.let { require(it is CryptoPublicKey.RSA);it }
        )
    }
/**
 * Obtains an Encryptor.
 *
 * @see PlatformDecryptorConfiguration
 */
fun AsymmetricEncryptionAlgorithm.RSA.encryptorFor(
    publicKey: CryptoPublicKey.RSA,
) = encryptorForImpl(publicKey)