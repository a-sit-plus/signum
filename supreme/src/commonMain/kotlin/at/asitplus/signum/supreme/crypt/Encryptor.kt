package at.asitplus.signum.supreme.crypt

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.AuthTrait
import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.EncryptionAlgorithm
import at.asitplus.signum.indispensable.mac.MAC
import at.asitplus.signum.supreme.mac.mac
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
): KmmResult<Encryptor<AuthTrait.Authenticated, EncryptionAlgorithm.Authenticated, Ciphertext.Authenticated>> =
    catching {
        Encryptor(this, secretKey, null, iv, aad, DefaultDedicatedMacInputCalculation)
    }

fun EncryptionAlgorithm.Unauthenticated.encryptorFor(
    secretKey: ByteArray,
    iv: ByteArray? = null,
): KmmResult<Encryptor<AuthTrait.Unauthenticated, EncryptionAlgorithm.Unauthenticated, Ciphertext.Unauthenticated>> =
    catching {
        Encryptor(this, secretKey, null, iv, null, DefaultDedicatedMacInputCalculation)
    }

fun EncryptionAlgorithm.WithDedicatedMac.encryptorFor(
    secretKey: ByteArray,
    dedicatedMacKey: ByteArray = secretKey,
    iv: ByteArray? = null,
    aad: ByteArray? = null,
    dedicatedMacAuthTagCalculation: DedicatedMacInputCalculation = DefaultDedicatedMacInputCalculation,
): KmmResult<Encryptor<AuthTrait.Authenticated, EncryptionAlgorithm.Authenticated, Ciphertext.Authenticated.WithDedicatedMac>> =
    catching {
        Encryptor(this, secretKey, dedicatedMacKey, iv, aad, dedicatedMacAuthTagCalculation)
    }


class Encryptor<A : AuthTrait, E : EncryptionAlgorithm<A>, C : Ciphertext<A, E>> internal constructor(
    private val algorithm: E,
    private val key: ByteArray,
    private val macKey: ByteArray?,
    private val iv: ByteArray?,
    private val aad: ByteArray?,
    private val macAuthTagCalculation: DedicatedMacInputCalculation
) {

    init {
        if (algorithm is EncryptionAlgorithm.WithIV<*>) iv?.let {
            require((it.size * 8).toUInt() == algorithm.ivNumBits) { "IV must be exactly ${algorithm.ivNumBits} bits long" }
        }
        require((key.size * 8).toUInt() == algorithm.keyNumBits) { "Key must be exactly ${algorithm.keyNumBits} bits long" }
    }


    private val platformCipher: CipherParam<*, A> = initCipher<Any, A, E>(algorithm, key, macKey, iv, aad)


    fun encrypt(data: ByteArray): KmmResult<C> {
        if (algorithm is EncryptionAlgorithm.AES.CBC.HMAC) {
            val aMac: EncryptionAlgorithm.WithDedicatedMac = algorithm
            val innerCipher = initCipher<Any, AuthTrait.Unauthenticated, EncryptionAlgorithm.AES.CBC.Plain>(
                algorithm.innerCipher,
                key,
                macKey,
                iv,
                aad
            )
            return catching {
                require(innerCipher.iv != null) { "AES-CBC-HMAC IV implementation error. Report this bug!" }
                require(macKey != null) { "AES-CBC-HMAC mac key implementation error. Report this bug!" }
                val encrypted = innerCipher.encrypt(data).getOrThrow().encryptedData

                val hmacInput: ByteArray =
                    aMac.mac.macAuthTagCalculation(encrypted, innerCipher.iv, (aad ?: byteArrayOf()))

                val maced = aMac.mac.mac(macKey, hmacInput).getOrThrow()
                return@catching Ciphertext.Authenticated.WithDedicatedMac(
                    aMac,
                    encrypted, innerCipher.iv, maced, aad
                ) as C
            }

        }
        return platformCipher.encrypt<A>(data) as KmmResult<C>
    }

}

typealias DedicatedMacInputCalculation = MAC.(ciphertext: ByteArray, iv: ByteArray?, aad: ByteArray?) -> ByteArray

/**
 * The default dedicated mac input calculation:
 * ```kotlin
 * (iv?: byteArrayOf()) + (aad ?: byteArrayOf()) + ciphertext
 * ```
 */
val DefaultDedicatedMacInputCalculation: DedicatedMacInputCalculation =
    fun MAC.(ciphertext: ByteArray, iv: ByteArray?, aad: ByteArray?): ByteArray =
        (iv ?: byteArrayOf()) + (aad ?: byteArrayOf()) + ciphertext


internal data class CipherParam<T, A : AuthTrait>(
    val alg: EncryptionAlgorithm<out A>,
    val platformData: T,
    val macKey: ByteArray,
    val iv: ByteArray?,
    val aad: ByteArray?
)

/**
 * Generates a new random key matching the key size of this algorithm
 */
fun EncryptionAlgorithm<*>.randomKey(): ByteArray = secureRandom.nextBytesOf((keyNumBits / 8u).toInt())

/**
 * Generates a new random IV matching the IV size of this algorithm
 */
fun EncryptionAlgorithm.WithIV<*>.randomIV(): ByteArray = secureRandom.nextBytesOf((ivNumBits / 8u).toInt())

internal expect fun <T, A : AuthTrait, E : EncryptionAlgorithm<A>> initCipher(
    algorithm: E,
    key: ByteArray,
    macKey: ByteArray?,
    iv: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A>

expect internal fun <A : AuthTrait> CipherParam<*, A>.encrypt(data: ByteArray): KmmResult<Ciphertext<A, EncryptionAlgorithm<A>>>


/**
 * Attempts to decrypt this ciphertext (which also holds IV, AAD, auth tag) using the provided [secretKey].
 * This method will fail before even trying to decrypt anything and immediately return [KmmResult.failure]
 * if the parameters and the algorithm don't match.
 */
fun <A : AuthTrait, E : EncryptionAlgorithm<A>> Ciphertext<A, E>.decrypt(secretKey: ByteArray): KmmResult<ByteArray> {
    catching {
        if (algorithm is EncryptionAlgorithm.WithIV<*>) {
            require(iv != null) { "IV must be non-null" }
            require(iv!!.size.toUInt() * 8u == (algorithm as EncryptionAlgorithm.WithIV<*>).ivNumBits) { "IV must be exactly ${(algorithm as EncryptionAlgorithm.WithIV<*>).ivNumBits} bits long" }
        }
        require(secretKey.size.toUInt() * 8u == algorithm.keyNumBits) { "Key must be exactly ${algorithm.keyNumBits} bits long" }

    }
    return when (this) {
        is Ciphertext.Authenticated -> doDecrypt(secretKey)
        is Ciphertext.Unauthenticated -> doDecrypt(secretKey)
    }
}

fun Ciphertext.Authenticated.WithDedicatedMac.decrypt(
    secretKey: ByteArray,
    macKey: ByteArray = secretKey,
    dedicatedMacInputCalculation: DedicatedMacInputCalculation = DefaultDedicatedMacInputCalculation
): KmmResult<ByteArray> {
    val hmacInput =
        algorithm.mac.dedicatedMacInputCalculation(encryptedData, iv, aad)

    if (!(algorithm.mac.mac(macKey, hmacInput).getOrThrow().contentEquals(this.authTag))) return KmmResult.failure(
        IllegalArgumentException("Auth Tag mismatch!")
    )
    return Ciphertext.Unauthenticated(algorithm.innerCipher, encryptedData, iv).decrypt(secretKey)
}

expect internal fun Ciphertext.Authenticated.doDecrypt(secretKey: ByteArray): KmmResult<ByteArray>

expect internal fun Ciphertext.Unauthenticated.doDecrypt(secretKey: ByteArray): KmmResult<ByteArray>