package at.asitplus.signum.supreme.crypt

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.EncryptionAlgorithm
import org.kotlincrypto.SecureRandom

private val secureRandom = SecureRandom()

/**
 * Creates an encryptor for the specified [secretKey]. Can be used to encrypt arbitrary data.
 * If no [iv] is specified, a random IV is generated.
 * [aad] = _Additional Authenticated Data_.
 * It is safe to discard the reference to [iv] and [aad], as both will be added to any [Ciphertext.Authenticated] resulting from an encryption.
 *
 * @return [KmmResult.success] containing an encryptor if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
fun EncryptionAlgorithm.Authenticated.encryptorFor(
    secretKey: ByteArray,
    iv: ByteArray? = null,
    aad: ByteArray? = null
): KmmResult<Encryptor<Ciphertext.Authenticated>> = catching {
    Encryptor(this, secretKey, iv, aad)
}


class Encryptor<T: Ciphertext> internal constructor(
    protected val algorithm: EncryptionAlgorithm,
    protected val key: ByteArray,
    protected val iv: ByteArray?,
    protected val aad: ByteArray?
) {

    init {
        if (algorithm is EncryptionAlgorithm.WithIV) iv?.let {
            require((it.size * 8).toUInt() == algorithm.ivNumBits) { "IV must be exactly ${algorithm.ivNumBits} bits long" }
        }
        require((key.size * 8).toUInt() == algorithm.keyNumBits) { "Key must be exactly ${algorithm.keyNumBits} bits long" }
    }


    private val platformCipher: PlatformCipher = initCipher(algorithm, key, iv, aad)


    fun encrypt(data: ByteArray): KmmResult<T> {
        return platformCipher.encrypt(data) as KmmResult<T>
    }

}

/**
 * Generates a new random key matching the key size of this algorithm
 */
fun EncryptionAlgorithm.randomKey(): ByteArray =secureRandom.nextBytesOf((keyNumBits/8u).toInt())


internal typealias PlatformCipher = Any

expect internal fun initCipher(
    algorithm: EncryptionAlgorithm,
    key: ByteArray,
    iv: ByteArray?,
    aad: ByteArray?
): PlatformCipher

expect internal fun PlatformCipher.encrypt(data: ByteArray): KmmResult<Ciphertext>

/**
 * Attempts to decrypt this ciphertext (which also holds IV, AAD, auth tag) using the provided [secretKey].
 * This method will fail before even trying to decrypt anything and immediately return [KmmResult.failure]
 * if the parameters and the algorithm don't match.
 */
fun Ciphertext.Authenticated.decrypt(secretKey: ByteArray): KmmResult<ByteArray> {
    catching {
        if (algorithm is EncryptionAlgorithm.WithIV) {
            require(iv != null) { "IV must be non-null" }
            require(iv!!.size.toUInt() * 8u == (algorithm as EncryptionAlgorithm.WithIV).ivNumBits) { "IV must be exactly ${(algorithm as EncryptionAlgorithm.WithIV).ivNumBits} bits long" }
        }
        require(secretKey.size.toUInt() * 8u == algorithm.keyNumBits) { "Key must be exactly ${algorithm.keyNumBits} bits long" }

    }
    return doDecrypt(secretKey)
}

expect internal fun Ciphertext.Authenticated.doDecrypt(secretKey: ByteArray): KmmResult<ByteArray>