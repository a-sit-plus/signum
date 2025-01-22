package at.asitplus.signum.supreme.crypt

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.CipherKind.Authenticated
import at.asitplus.signum.indispensable.SymmetricKey.Integrated
import at.asitplus.signum.indispensable.SymmetricKey.WithDedicatedMac
import at.asitplus.signum.indispensable.mac.MAC
import at.asitplus.signum.supreme.mac.mac
import org.kotlincrypto.SecureRandom
import kotlin.jvm.JvmName

internal val secureRandom = SecureRandom()


@HazardousMaterials
@JvmName("encryptWithIV")
fun SymmetricKey<*, IV.Required>.encrypt(
    iv: ByteArray,
    data: ByteArray
): KmmResult<SealedBox.WithIV<*, SymmetricEncryptionAlgorithm<*, IV.Required>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
        iv,
        null,
        DefaultDedicatedMacInputCalculation
    ).encrypt(data) as SealedBox.WithIV<*, SymmetricEncryptionAlgorithm<*, IV.Required>>
}


/**
 * Encrypts [data] and automagically generates a fresh IV if required by the cipher.
 *
 * @return [KmmResult.success] containing a [Ciphertext] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
fun <A : CipherKind> SymmetricKey<A, *>.encrypt(
    data: ByteArray,
): KmmResult<SealedBox<A, *, SymmetricEncryptionAlgorithm<A, *>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
        null,
        null,
        DefaultDedicatedMacInputCalculation
    ).encrypt(data)
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
fun SymmetricKey<Authenticated, IV.Required>.encrypt(
    iv: ByteArray,
    data: ByteArray,
    aad: ByteArray? = null
): KmmResult<SealedBox.WithIV<Authenticated, SymmetricEncryptionAlgorithm<Authenticated, IV.Required>>> =
    catching {
        Encryptor(
            algorithm,
            secretKey,
            if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
            iv,
            aad,
            DefaultDedicatedMacInputCalculation
        ).encrypt(data) as SealedBox.WithIV<Authenticated, SymmetricEncryptionAlgorithm<Authenticated, IV.Required>>
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
fun SymmetricKey<Authenticated, *>.encrypt(
    data: ByteArray,
    aad: ByteArray? = null
): KmmResult<SealedBox<Authenticated, *, SymmetricEncryptionAlgorithm<Authenticated, *>>> =
    catching {
        Encryptor(
            algorithm,
            secretKey,
            if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
            null,
            aad,
            DefaultDedicatedMacInputCalculation
        ).encrypt(data)
    }
/*
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
fun <A : CipherKind> SymmetricKey.Integrated<SymmetricEncryptionAlgorithm.WithIV<A>>.encrypt(
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
*/

/*
/**
 * Encrypts [data] and automagically generates a fresh IV if required by the cipher.
 *
 * @return [KmmResult.success] containing a [Ciphertext] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
@JvmName("encryptUnauthenticated")
fun SymmetricKey<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm.Unauthenticated>.encrypt(
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
*/

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
fun SymmetricKey.WithDedicatedMac<IV.Required>.encrypt(
    iv: ByteArray,
    data: ByteArray,
    aad: ByteArray? = null,
    dedicatedMacAuthTagCalculation: DedicatedMacInputCalculation = DefaultDedicatedMacInputCalculation,
): KmmResult<SealedBox.WithIV<Authenticated.WithDedicatedMac<*, IV.Required>,
        SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        dedicatedMacKey,
        iv,
        aad,
        dedicatedMacAuthTagCalculation
    ).encrypt(data) as SealedBox.WithIV<Authenticated.WithDedicatedMac<*, IV.Required>,
            SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>>
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
fun SymmetricKey.WithDedicatedMac<*>.encrypt(
    data: ByteArray,
    aad: ByteArray? = null,
    dedicatedMacAuthTagCalculation: DedicatedMacInputCalculation = DefaultDedicatedMacInputCalculation,
): KmmResult<SealedBox<Authenticated.WithDedicatedMac<*, *>, *,
        SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, *>, *>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        dedicatedMacKey,
        null,
        aad,
        dedicatedMacAuthTagCalculation
    ).encrypt(data)
}


internal class Encryptor<A : CipherKind, E : SymmetricEncryptionAlgorithm<A, *>, C : SealedBox<A, *, E>> internal constructor(
    private val algorithm: E,
    private val key: ByteArray,
    private val macKey: ByteArray?,
    private val iv: ByteArray?,
    private val aad: ByteArray?,
    private val macAuthTagCalculation: DedicatedMacInputCalculation
) {

    init {
        if (algorithm.iv is IV.Required) iv?.let {
            require(it.size.toUInt() == (algorithm.iv as IV.Required).ivLen.bytes) { "IV must be exactly ${(algorithm.iv as IV.Required).ivLen} bits long" }
        }
        require(key.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    }


    private val platformCipher: CipherParam<*, A> = initCipher<Any, A, E>(algorithm, key, iv, aad)

    /**
     * Encrypts [data] and returns a [Ciphertext] matching the algorithm type that was used to create this [Encryptor] object.
     * E.g., an authenticated encryption algorithm causes this function to return a [Ciphertext.Authenticated].
     */
    fun encrypt(data: ByteArray): C = if (algorithm.cipher is Authenticated.WithDedicatedMac<*, *>) {
        val aMac = algorithm.cipher as Authenticated.WithDedicatedMac<*, *>
        aMac.innerCipher
        val t = aMac.innerCipher::class
        val innerCipher =
            initCipher<Any, CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>>(
                aMac.innerCipher,
                key,
                iv,
                aad
            )

        require(innerCipher.iv != null) { "IV implementation error. Report this bug!" }
        require(macKey != null) { "MAC key implementation error. Report this bug!" }
        val encrypted = innerCipher.doEncrypt<CipherKind.Unauthenticated, IV>(data)

        val hmacInput: ByteArray =
            aMac.mac.macAuthTagCalculation(
                encrypted.ciphertext.encryptedData,
                innerCipher.iv,
                (aad ?: byteArrayOf())
            )

        val maced = aMac.mac.mac(macKey, hmacInput).getOrThrow()

        val ciphertext = Ciphertext.Authenticated.WithDedicatedMac(
            algorithm as SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, *>, *>,
            encrypted.ciphertext.encryptedData,
            maced,
            aad
        )

        (if (algorithm.iv is IV.Required)
            SealedBox.WithIV<A, SymmetricEncryptionAlgorithm<A, IV.Required>>(
                (encrypted as SealedBox.WithIV<*, *>).iv,
                ciphertext as Ciphertext<A, SymmetricEncryptionAlgorithm<A, IV.Required>>
            )
        else
            SealedBox.WithoutIV<A, SymmetricEncryptionAlgorithm<A, IV.Without>>(ciphertext as Ciphertext<A, SymmetricEncryptionAlgorithm<A, IV.Without>>)
                ) as C


    } else platformCipher.doEncrypt<A, IV>(data) as C


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


internal class CipherParam<T, A : CipherKind>(
    val alg: SymmetricEncryptionAlgorithm<A, *>,
    val platformData: T,
    val iv: ByteArray?,
    val aad: ByteArray?
)

@JvmName("doEncryptUnauthenticated")
fun SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>.randomKey(): SymmetricKey<CipherKind.Unauthenticated, *> =
    Integrated<CipherKind.Unauthenticated, IV>(this, secureRandom.nextBytesOf(keySize.bytes.toInt()))

@JvmName("doEncryptAuthenticatedIntegrated")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>.randomKey(): SymmetricKey<CipherKind.Authenticated.Integrated, *> =
    Integrated<CipherKind.Authenticated.Integrated, IV>(this, secureRandom.nextBytesOf(keySize.bytes.toInt()))

fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, *>, *>.randomKey(): SymmetricKey<CipherKind.Authenticated.WithDedicatedMac<*, *>, *> =
    Integrated<CipherKind.Authenticated.WithDedicatedMac<*, *>, IV>(
        this,
        secureRandom.nextBytesOf(keySize.bytes.toInt())
    )

/**
 * Generates a new random IV matching the IV size of this algorithm
 */
internal fun SymmetricEncryptionAlgorithm<*, IV.Required>.randomIV() =
    @OptIn(HazardousMaterials::class) secureRandom.nextBytesOf((iv.ivLen.bytes).toInt())


/**
 * Attempts to decrypt this ciphertext (which also holds IV, and in case of an authenticated ciphertext, AAD and auth tag) using the provided [key].
 * This is the function you typically want to use.
 */
fun <A : CipherKind, I : IV> SealedBox<A, I, *>.decrypt(key: SymmetricKey<out A, I>): KmmResult<ByteArray> = catching {
    require(ciphertext.algorithm == key.algorithm) { "Somebody likes cursed casts!" }
    if(ciphertext is Ciphertext.Authenticated.WithDedicatedMac) {
        val authTag = (ciphertext as Ciphertext.Authenticated.WithDedicatedMac).authTag
        (this as SealedBox<CipherKind.Authenticated.WithDedicatedMac<*, *>, *, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, *>, *>>).decrypt(
            key.secretKey, (key as SymmetricKey.WithDedicatedMac<*>).dedicatedMacKey
        )
    }
    decrypt(key.secretKey).getOrThrow()
}

/**
 * Attempts to decrypt this ciphertext using the provided raw [secretKey].
 */
fun SealedBox<*, *, *>.decrypt(secretKey: ByteArray): KmmResult<ByteArray> =
    catching {
        require(secretKey.size.toUInt() == ciphertext.algorithm.keySize.bytes) { "Key must be exactly ${ciphertext.algorithm.keySize} bits long" }
        when (ciphertext) {
            is Ciphertext.Authenticated.Integrated -> (this as SealedBox<CipherKind.Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<Authenticated.Integrated, *>>).doDecrypt(
                secretKey
            )

            is Ciphertext.Unauthenticated -> (this as SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>>).doDecrypt(
                secretKey
            )

            is Ciphertext.Authenticated.WithDedicatedMac -> (this as SealedBox<CipherKind.Authenticated.WithDedicatedMac<*, *>, *, SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, *>, *>>).decrypt(
                secretKey
            ).getOrThrow()
        }
    }

/**
 * Attempts to decrypt this ciphertext using the provided raw [secretKey].
 * If no [macKey] is provided, [secretKey] will be used as MAC key.
 * [dedicatedMacInputCalculation] can be used to override the [DefaultDedicatedMacInputCalculation] used to compute MAC input.
 */

fun SealedBox<CipherKind.Authenticated.WithDedicatedMac<*, *>, *, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, *>, *>>.decrypt(
    secretKey: ByteArray,
    macKey: ByteArray = secretKey,
    dedicatedMacInputCalculation: DedicatedMacInputCalculation = DefaultDedicatedMacInputCalculation
): KmmResult<ByteArray> = catching {
    val iv: ByteArray? = if (this is SealedBox.WithIV<*, *>) iv else null
    val aad = (ciphertext as Ciphertext.Authenticated).authenticatedData
    val authTag = (ciphertext as Ciphertext.Authenticated).authTag

    val algorithm = ciphertext.algorithm
    val innerCipher = ciphertext.algorithm.cipher.innerCipher
    val mac = algorithm.cipher.mac
    val hmacInput = mac.dedicatedMacInputCalculation(ciphertext.encryptedData, iv, aad)
    if (!(mac.mac(macKey, hmacInput).getOrThrow().contentEquals(authTag))) return KmmResult.failure(
        IllegalArgumentException("Auth Tag mismatch!")
    )
    val innerCipherText: Ciphertext.Unauthenticated = Ciphertext.Unauthenticated(innerCipher, ciphertext.encryptedData)
    val box: SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>> =
        (
                if (this is SealedBox.WithIV<*, *>) SealedBox.WithIV<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Required>>(
                    iv!!,
                    innerCipherText as Ciphertext<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Required>>
                )
                else SealedBox.WithoutIV<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Without>>(
                    innerCipherText as Ciphertext<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Without>>
                )
                ) as SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>>
    box.doDecrypt(secretKey)
}


expect internal fun SealedBox<CipherKind.Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray

expect internal fun SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray


internal expect fun <T, A : CipherKind, E : SymmetricEncryptionAlgorithm<A, *>> initCipher(
    algorithm: E,
    key: ByteArray,
    iv: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A>

internal expect fun <A : CipherKind, I : IV> CipherParam<*, A>.doEncrypt(data: ByteArray): SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>>

