package at.asitplus.signum.supreme.asymmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn


sealed interface Encryptor {
    val algorithm: AsymmetricEncryptionAlgorithm
    val publicKey: CryptoPublicKey

    /**
     * Works around the pathological behavior of KmmResult<Unit> with .map, which would make
     * ```
     * val proxyVerify(...): KmmResult<Unit> = getVerifier().map { it.verify(...) }
     * ```
     * silently succeed (with the programmer confusing `map` and `transform`).
     */
    data object Success

    fun encrypt(data: ByteArray): KmmResult<ByteArray>


    sealed class RSA(
        final override val algorithm: AsymmetricEncryptionAlgorithm.RSA,
        final override val publicKey: CryptoPublicKey.RSA
    ) : Encryptor
}

expect class PlatformEncryptorConfiguration internal constructor() : DSL.Data
typealias ConfigurePlatformEncryptor = DSLConfigureFn<PlatformEncryptorConfiguration>


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
 *
 * @see PlatformEncryptorConfiguration
 */
fun AsymmetricEncryptionAlgorithm.encryptorFor(
    publicKey: CryptoPublicKey,
    configure: ConfigurePlatformEncryptor = null
) = encryptorForImpl(publicKey, configure)

private fun AsymmetricEncryptionAlgorithm.encryptorForImpl(
    publicKey: CryptoPublicKey, configure: ConfigurePlatformEncryptor,
): Encryptor =
    when (this) {
        is AsymmetricEncryptionAlgorithm.RSA -> PlatformRSAEncryptor(
            this,
            publicKey.let { require(it is CryptoPublicKey.RSA);it },
            configure
        )
    }
/**
 * Obtains an Encryptor.
 *
 * @see PlatformEncryptorConfiguration
 */
fun AsymmetricEncryptionAlgorithm.RSA.encryptorFor(
    publicKey: CryptoPublicKey.RSA,
    configure: ConfigurePlatformEncryptor = null
) = encryptorForImpl(publicKey, configure)