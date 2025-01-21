package at.asitplus.signum.supreme.crypt

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.AuthTrait
import at.asitplus.signum.indispensable.AuthTrait.Authenticated
import at.asitplus.signum.indispensable.AuthTrait.Unauthenticated
import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.SymmetricKey
import at.asitplus.signum.indispensable.SymmetricKey.Integrated
import at.asitplus.signum.indispensable.SymmetricKey.WithDedicatedMac
import at.asitplus.signum.indispensable.mac.MAC
import at.asitplus.signum.supreme.mac.mac
import org.kotlincrypto.SecureRandom
import kotlin.jvm.JvmName

internal val secureRandom = SecureRandom()

@HazardousMaterials
@JvmName("encryptWithIV")
fun SymmetricKey<*, out SymmetricEncryptionAlgorithm.WithIV<*>>.encrypt(
    iv: ByteArray,
    data: ByteArray
) : KmmResult<Ciphertext< *, out SymmetricEncryptionAlgorithm.WithIV<*>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        if(this is WithDedicatedMac) dedicatedMacKey else secretKey,
        iv,
        null,
        DefaultDedicatedMacInputCalculation
    ).encrypt(data) as Ciphertext<*, out SymmetricEncryptionAlgorithm.WithIV<*>>
}


/**
 * Encrypts [data] and automagically generates a fresh IV if required by the cipher.
 *
 * @return [KmmResult.success] containing a [Ciphertext] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
fun <A : AuthTrait> SymmetricKey<out A, out SymmetricEncryptionAlgorithm<A>>.encrypt(
    data: ByteArray,
): KmmResult<Ciphertext<A, SymmetricEncryptionAlgorithm<A>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        if(this is WithDedicatedMac) dedicatedMacKey else secretKey,
        null,
        null,
        DefaultDedicatedMacInputCalculation
    ).encrypt(data) as Ciphertext<A, SymmetricEncryptionAlgorithm<A>>
}

/**
 * Encrypts [data] using a specified IV. Check yourself, before you really, really wreck yourself!
 * * [iv] =  _Initialization Vector_; **NEVER EVER RE-USE THIS!**
 * * [aad] = _Additional Authenticated Data_
 *
 * It is safe to discard the reference to [iv] and [aad], as both will be added to any [Ciphertext.Authenticated] resulting from an encryption.
 *
 * @return [KmmResult.success] containing a [Ciphertext.Authenticated] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
@HazardousMaterials
fun  SymmetricKey<out Authenticated, out SymmetricEncryptionAlgorithm.WithIV<Authenticated>>.encrypt(
    iv: ByteArray,
    data: ByteArray,
    aad: ByteArray? = null
): KmmResult<Ciphertext.Authenticated> =
    catching {
        Encryptor(
            algorithm,
            secretKey,
            if(this is WithDedicatedMac) dedicatedMacKey else secretKey,
            iv,
            aad,
            DefaultDedicatedMacInputCalculation
        ).encrypt(data) as Ciphertext.Authenticated
    }

/**
 * Encrypts [data] and automagically generates a fresh IV if required by the cipher.
 * This is the method you want to use, as it generates a fresh IV, if the underlying cipher requires an IV.
 * * [aad] = _Additional Authenticated Data_
 *
 * It is safe to discard the reference to [aad], as both IV and AAD will be added to any [Ciphertext.Authenticated] resulting from an encryption.
 *
 * @return [KmmResult.success] containing a [Ciphertext.Authenticated] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
@JvmName("encryptAuthenticated")
fun SymmetricKey<AuthTrait.Authenticated, SymmetricEncryptionAlgorithm.Authenticated<*>>.encrypt(
    data: ByteArray,
    aad: ByteArray? = null
): KmmResult<Ciphertext.Authenticated> =
    catching {
        Encryptor(
            algorithm,
            secretKey,
            if(this is WithDedicatedMac) dedicatedMacKey else secretKey,
            null,
            aad,
            DefaultDedicatedMacInputCalculation
        ).encrypt(data) as Ciphertext.Authenticated
    }

/**
 * Encrypts [data] using a specified IV. Check yourself, before you really, really wreck yourself!
 * * [iv] =  _Initialization Vector_; **NEVER EVER RE-USE THIS!**
 *
 * It is safe to discard the reference to [iv], as it will be added to any [Ciphertext] resulting from an encryption.
 *
 * @return [KmmResult.success] containing a [Ciphertext] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
@HazardousMaterials
fun <A : AuthTrait> SymmetricKey.Integrated<SymmetricEncryptionAlgorithm.WithIV<A>>.encrypt(
    iv: ByteArray,
    data: ByteArray,
): KmmResult<Ciphertext<A, SymmetricEncryptionAlgorithm.WithIV<A>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        null,
        iv,
        null,
        DefaultDedicatedMacInputCalculation
    ).encrypt(data) as Ciphertext<A, SymmetricEncryptionAlgorithm.WithIV<A>>
}


/**
 * Encrypts [data] and automagically generates a fresh IV if required by the cipher.
 *
 * @return [KmmResult.success] containing a [Ciphertext] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
@JvmName("encryptUnauthenticated")
fun SymmetricKey<AuthTrait.Unauthenticated, SymmetricEncryptionAlgorithm.Unauthenticated>.encrypt(
    data: ByteArray,
): KmmResult<Ciphertext.Unauthenticated> = catching {
    Encryptor(
        algorithm,
        secretKey,
        null,
        null,
        null,
        DefaultDedicatedMacInputCalculation
    ).encrypt(data) as Ciphertext.Unauthenticated
}




/**
 * Encrypts [data] using a specified IV. Check yourself, before you really, really wreck yourself!
 * * [iv] =  _Initialization Vector_; **NEVER EVER RE-USE THIS!**
 * * [aad] = _Additional Authenticated Data_
 * * [dedicatedMacKey] should be used to specify a dedicated MAC key, unless indicated otherwise. Defaults to [secretKey]
 * * [dedicatedMacAuthTagCalculation] can be used to specify a custom computation for the MAC input. Defaults to [DefaultDedicatedMacInputCalculation].
 *
 * It is safe to discard the reference to [iv] and [aad], as both will be added to any [Ciphertext.Authenticated.WithDedicatedMac] resulting from an encryption.
 *
 * @return [KmmResult.success] containing a [Ciphertext.Authenticated.WithDedicatedMac] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
@HazardousMaterials
fun SymmetricKey.WithDedicatedMac.encrypt(
    iv: ByteArray,
    data: ByteArray,
    aad: ByteArray? = null,
    dedicatedMacAuthTagCalculation: DedicatedMacInputCalculation = DefaultDedicatedMacInputCalculation,
): KmmResult<Ciphertext.Authenticated.WithDedicatedMac> = catching {
    Encryptor(
        algorithm,
        secretKey,
        dedicatedMacKey,
        iv,
        aad,
        dedicatedMacAuthTagCalculation
    ).encrypt(data) as Ciphertext.Authenticated.WithDedicatedMac
}

/**
 * Encrypts [data] and automagically generates a fresh IV if required by the cipher.
 * * [aad] = _Additional Authenticated Data_
 * * [dedicatedMacKey] should be used to specify a dedicated MAC key, unless indicated otherwise. Defaults to [secretKey]
 * * [dedicatedMacAuthTagCalculation] can be used to specify a custom computation for the MAC input. Defaults to [DefaultDedicatedMacInputCalculation].
 *
 * It is safe to discard the reference to [aad], as both AAD and iV will be added to any [Ciphertext.Authenticated.WithDedicatedMac] resulting from an encryption.
 *
 * @return [KmmResult.success] containing a [Ciphertext.Authenticated.WithDedicatedMac] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
fun SymmetricKey.WithDedicatedMac.encrypt(
    data: ByteArray,
    aad: ByteArray? = null,
    dedicatedMacAuthTagCalculation: DedicatedMacInputCalculation = DefaultDedicatedMacInputCalculation,
): KmmResult<Ciphertext.Authenticated.WithDedicatedMac> = catching {
    Encryptor(
        algorithm,
        secretKey,
        dedicatedMacKey,
        null,
        aad,
        dedicatedMacAuthTagCalculation
    ).encrypt(data) as Ciphertext.Authenticated.WithDedicatedMac
}


internal class Encryptor<A : AuthTrait, E : SymmetricEncryptionAlgorithm<A>, C : Ciphertext<A, E>> internal constructor(
    private val algorithm: E,
    private val key: ByteArray,
    private val macKey: ByteArray?,
    private val iv: ByteArray?,
    private val aad: ByteArray?,
    private val macAuthTagCalculation: DedicatedMacInputCalculation
) {

    init {
        if (algorithm is SymmetricEncryptionAlgorithm.WithIV<*>) iv?.let {
            require(it.size.toUInt() == algorithm.ivLen.bytes) { "IV must be exactly ${algorithm.ivLen} bits long" }
        }
        require(key.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    }


    private val platformCipher: CipherParam<*, A> = initCipher<Any, A, E>(algorithm, key, iv, aad)

    /**
     * Encrypts [data] and returns a [Ciphertext] matching the algorithm type that was used to create this [Encryptor] object.
     * E.g., an authenticated encryption algorithm causes this function to return a [Ciphertext.Authenticated].
     */
    fun encrypt(data: ByteArray): C {
        if (algorithm is SymmetricEncryptionAlgorithm.AES.CBC.HMAC) {
            val aMac: SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac = algorithm
            val innerCipher = initCipher<Any, AuthTrait.Unauthenticated, SymmetricEncryptionAlgorithm.AES.CBC.Plain>(
                algorithm.innerCipher,
                key,
                iv,
                aad
            )

            require(innerCipher.iv != null) { "AES-CBC-HMAC IV implementation error. Report this bug!" }
            require(macKey != null) { "AES-CBC-HMAC mac key implementation error. Report this bug!" }
            val encrypted = innerCipher.doEncrypt(data).encryptedData

            val hmacInput: ByteArray =
                aMac.mac.macAuthTagCalculation(encrypted, innerCipher.iv, (aad ?: byteArrayOf()))

            val maced = aMac.mac.mac(macKey, hmacInput).getOrThrow()
            return Ciphertext.Authenticated.WithDedicatedMac(
                aMac,
                encrypted, innerCipher.iv, maced, aad
            ) as C


        }
        return platformCipher.doEncrypt<A>(data) as C
    }

}
/**
 * Typealias defining the signature of the lambda for defining a custom MAC input calculation scheme.
 */
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


internal class CipherParam<T, A : AuthTrait>(
    val alg: SymmetricEncryptionAlgorithm<A>,
    val platformData: T,
    val iv: ByteArray?,
    val aad: ByteArray?
)

/**
 * Generates a new random key matching the key size of this algorithm
 */
fun SymmetricEncryptionAlgorithm.Authenticated.Integrated.randomKey(): SymmetricKey.Integrated<Authenticated.Integrated> =
    Integrated(this, secureRandom.nextBytesOf(keySize.bytes.toInt()))

/**
 * Generates a new random key matching the key size of this algorithm
 */
fun SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac.randomKey(dedicatedMacKeyOverride: ByteArray?=null): SymmetricKey.WithDedicatedMac {
    val secretKey = secureRandom.nextBytesOf(keySize.bytes.toInt())
    return WithDedicatedMac(this, secretKey, dedicatedMacKeyOverride?:secretKey)
}

/**
 * Generates a new random key matching the key size of this algorithm
 */
@JvmName("randomKeyWithIV")
fun <A: AuthTrait>SymmetricEncryptionAlgorithm.WithIV<A>.randomKey(): SymmetricKey<out A,  out SymmetricEncryptionAlgorithm.WithIV<A>> =
    when(this){
        is SymmetricEncryptionAlgorithm.Unauthenticated, is SymmetricEncryptionAlgorithm.Authenticated.Integrated ->  Integrated(this, secureRandom.nextBytesOf(keySize.bytes.toInt()))
        is SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac -> secureRandom.nextBytesOf(keySize.bytes.toInt()).let { WithDedicatedMac(this, secretKey = it) }
        else -> TODO()
    }as  SymmetricKey<out A,  out SymmetricEncryptionAlgorithm.WithIV<A>>



/**
 * Generates a new random key matching the key size of this algorithm
 */
@JvmName("randomKeyWithIVAuthenticated")
fun SymmetricEncryptionAlgorithm.WithIV<Authenticated>.randomKey(): SymmetricKey<out Authenticated, out SymmetricEncryptionAlgorithm.WithIV<Authenticated>> =
    when(this){
        is SymmetricEncryptionAlgorithm.Authenticated.Integrated ->  Integrated(this, secureRandom.nextBytesOf(keySize.bytes.toInt()))
        is SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac -> secureRandom.nextBytesOf(keySize.bytes.toInt()).let { WithDedicatedMac(this, secretKey = it) }
        else -> TODO()
    }  as SymmetricKey<out Authenticated, out SymmetricEncryptionAlgorithm.WithIV<Authenticated>>


/**
 * Generates a new random IV matching the IV size of this algorithm
 */
internal fun SymmetricEncryptionAlgorithm.WithIV<*>.randomIV() =
    @OptIn(HazardousMaterials::class) secureRandom.nextBytesOf((ivLen.bytes).toInt())

/**
 * Attempts to decrypt this ciphertext (which also holds IV, and in case of an authenticated ciphertext, AAD and auth tag) using the provided [secretKey].
 */
fun <A : AuthTrait, E : SymmetricEncryptionAlgorithm<A>> Ciphertext<A, E>.decrypt(secretKey: ByteArray): KmmResult<ByteArray> =
    catching {

        if (algorithm is SymmetricEncryptionAlgorithm.WithIV<*>) {
            require(iv != null) { "IV must be non-null" }
            require(iv!!.size.toUInt() == (algorithm as SymmetricEncryptionAlgorithm.WithIV<*>).ivLen.bytes) { "IV must be exactly ${(algorithm as SymmetricEncryptionAlgorithm.WithIV<*>).ivLen} bits long" }
        }
        require(secretKey.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }

        when (this) {
            is Ciphertext.Authenticated -> doDecrypt(secretKey)
            is Ciphertext.Unauthenticated -> doDecrypt(secretKey)
        }
    }

/**
 * Attempts to decrypt this ciphertext (which also holds IV, AAD, and auth tag) using the provided [secretKey].
 * If no [macKey] is provided, [secretKey] will be used as MAC key.
 * [dedicatedMacInputCalculation] can be used to override the [DefaultDedicatedMacInputCalculation] used to compute MAC input.
 */
fun Ciphertext.Authenticated.WithDedicatedMac.decrypt(
    secretKey: ByteArray,
    macKey: ByteArray = secretKey,
    dedicatedMacInputCalculation: DedicatedMacInputCalculation = DefaultDedicatedMacInputCalculation
): KmmResult<ByteArray> {
    val hmacInput =
        algorithm.mac.dedicatedMacInputCalculation(encryptedData, iv, authenticatedData)

    if (!(algorithm.mac.mac(macKey, hmacInput).getOrThrow().contentEquals(this.authTag))) return KmmResult.failure(
        IllegalArgumentException("Auth Tag mismatch!")
    )
    return Ciphertext.Unauthenticated(algorithm.innerCipher, encryptedData, iv).decrypt(secretKey)
}

expect internal fun Ciphertext.Authenticated.doDecrypt(secretKey: ByteArray): ByteArray

expect internal fun Ciphertext.Unauthenticated.doDecrypt(secretKey: ByteArray): ByteArray


internal expect fun <T, A : AuthTrait, E : SymmetricEncryptionAlgorithm<A>> initCipher(
    algorithm: E,
    key: ByteArray,
    iv: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A>

internal expect fun <A : AuthTrait> CipherParam<*, A>.doEncrypt(data: ByteArray): Ciphertext<A, SymmetricEncryptionAlgorithm<A>>

