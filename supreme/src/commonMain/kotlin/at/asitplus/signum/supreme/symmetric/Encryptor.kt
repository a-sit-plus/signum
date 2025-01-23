package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.mac.MAC
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.CipherKind.Authenticated
import at.asitplus.signum.indispensable.symmetric.SymmetricKey.WithDedicatedMac
import at.asitplus.signum.supreme.mac.mac
import org.kotlincrypto.SecureRandom
import kotlin.jvm.JvmName

internal val secureRandom = SecureRandom()


@HazardousMaterials
@JvmName("encryptWithIVAuthenticated")
fun SymmetricKey<CipherKind.Authenticated, IV.Required>.encrypt(
    iv: ByteArray,
    data: ByteArray
): KmmResult<SealedBox.WithIV<CipherKind.Authenticated, SymmetricEncryptionAlgorithm<Authenticated, IV.Required>>> =
    (this as SymmetricKey<*, IV.Required>).encrypt(
        iv,
        data
    ) as KmmResult<SealedBox.WithIV<Authenticated, SymmetricEncryptionAlgorithm<Authenticated, IV.Required>>>


@HazardousMaterials
@JvmName("encryptWithIVUnuthenticated")
fun SymmetricKey<CipherKind.Unauthenticated, IV.Required>.encrypt(
    iv: ByteArray,
    data: ByteArray
): KmmResult<SealedBox.WithIV<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Required>>> =
    (this as SymmetricKey<*, IV.Required>).encrypt(
        iv,
        data
    ) as KmmResult<SealedBox.WithIV<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Required>>>


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

@JvmName("encryptWithAutGenIV")
fun SymmetricKey<*, IV.Required>.encrypt(
    data: ByteArray
): KmmResult<SealedBox.WithIV<*, SymmetricEncryptionAlgorithm<*, IV.Required>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
        null,
        null,
        DefaultDedicatedMacInputCalculation
    ).encrypt(data) as SealedBox.WithIV<*, SymmetricEncryptionAlgorithm<*, IV.Required>>
}

@HazardousMaterials
@JvmName("encryptAuthenticatedWithIV")
fun <A : CipherKind.Authenticated> SymmetricKey<A, IV.Required>.encrypt(
    iv: ByteArray,
    data: ByteArray
): KmmResult<SealedBox.WithIV<A, SymmetricEncryptionAlgorithm<A, IV.Required>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
        iv,
        null,
        DefaultDedicatedMacInputCalculation
    ).encrypt(data) as SealedBox.WithIV<A, SymmetricEncryptionAlgorithm<A, IV.Required>>
}


/**
 * Encrypts [data] and automagically generates a fresh IV if required by the cipher.
 *
 * @return [KmmResult.success] containing a [at.asitplus.signum.indispensable.symmetric.Ciphertext] if valid parameters were provided or [KmmResult.failure] in case of
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
 * * [authenticatedData] = _Additional Authenticated Data_
 *
 * It is safe to discard the reference to [iv] and [authenticatedData], as both will be added to any [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated] resulting from an encryption.
 *
 * @return [KmmResult.success] containing a [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
@HazardousMaterials
fun SymmetricKey<Authenticated, IV.Required>.encrypt(
    iv: ByteArray,
    data: ByteArray,
    authenticatedData: ByteArray? = null
): KmmResult<SealedBox.WithIV<Authenticated, SymmetricEncryptionAlgorithm<Authenticated, IV.Required>>> =
    catching {
        Encryptor(
            algorithm,
            secretKey,
            if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
            iv,
            authenticatedData,
            DefaultDedicatedMacInputCalculation
        ).encrypt(data) as SealedBox.WithIV<Authenticated, SymmetricEncryptionAlgorithm<Authenticated, IV.Required>>
    }

@HazardousMaterials
@JvmName("encryptAuthenticatedWithIVAndAAD")
fun SymmetricKey<Authenticated.Integrated, IV.Required>.encrypt(
    iv: ByteArray,
    data: ByteArray,
    authenticatedData: ByteArray? = null
): KmmResult<SealedBox.WithIV<Authenticated, SymmetricEncryptionAlgorithm<Authenticated, IV.Required>>> =
    catching {
        Encryptor(
            algorithm,
            secretKey,
            if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
            iv,
            authenticatedData,
            DefaultDedicatedMacInputCalculation
        ).encrypt(data) as SealedBox.WithIV<Authenticated, SymmetricEncryptionAlgorithm<Authenticated, IV.Required>>
    }

/**
 * Encrypts [data] and automagically generates a fresh IV if required by the cipher.
 * This is the method you want to use, as it generates a fresh IV, if the underlying cipher requires an IV.
 * * [autehnticatedData] = _Additional Authenticated Data_
 *
 * It is safe to discard the reference to [autehnticatedData], as both IV and AAD will be added to any [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated] resulting from an encryption.
 *
 * @return [KmmResult.success] containing a [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
@JvmName("encryptAuthenticated")
fun SymmetricKey<Authenticated, *>.encrypt(
    data: ByteArray,
    autehnticatedData: ByteArray? = null
): KmmResult<SealedBox<Authenticated, *, SymmetricEncryptionAlgorithm<Authenticated, *>>> =
    catching {
        Encryptor(
            algorithm,
            secretKey,
            if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
            null,
            autehnticatedData,
            DefaultDedicatedMacInputCalculation
        ).encrypt(data)
    }

/**
 * Encrypts [data] using a specified IV. Check yourself, before you really, really wreck yourself!
 * * [iv] =  _Initialization Vector_; **NEVER EVER RE-USE THIS!**
 * * [authenticatedData] = _Additional Authenticated Data_
 * * [dedicatedMacKey] should be used to specify a dedicated MAC key, unless indicated otherwise. Defaults to [secretKey]
 * * [dedicatedMacAuthTagCalculation] can be used to specify a custom computation for the MAC input. Defaults to [DefaultDedicatedMacInputCalculation].
 *
 * It is safe to discard the reference to [iv] and [authenticatedData], as both will be added to any [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated.WithDedicatedMac] resulting from an encryption.
 *
 * @return [KmmResult.success] containing a [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated.WithDedicatedMac] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
@HazardousMaterials
fun SymmetricKey.WithDedicatedMac<IV.Required>.encrypt(
    iv: ByteArray,
    data: ByteArray,
    authenticatedData: ByteArray? = null,
    dedicatedMacAuthTagCalculation: DedicatedMacInputCalculation = DefaultDedicatedMacInputCalculation,
): KmmResult<SealedBox.WithIV<Authenticated.WithDedicatedMac<*, IV.Required>,
        SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        dedicatedMacKey,
        iv,
        authenticatedData,
        dedicatedMacAuthTagCalculation
    ).encrypt(data) as SealedBox.WithIV<Authenticated.WithDedicatedMac<*, IV.Required>,
            SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>>
}

/**
 * Encrypts [data] and automagically generates a fresh IV if required by the cipher.
 * * [authenticatedData] = _Additional Authenticated Data_
 * * [dedicatedMacKey] should be used to specify a dedicated MAC key, unless indicated otherwise. Defaults to [secretKey]
 * * [dedicatedMacAuthTagCalculation] can be used to specify a custom computation for the MAC input. Defaults to [DefaultDedicatedMacInputCalculation].
 *
 * It is safe to discard the reference to [authenticatedData], as both AAD and iV will be added to any [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated.WithDedicatedMac] resulting from an encryption.
 *
 * @return [KmmResult.success] containing a [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated.WithDedicatedMac] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
fun SymmetricKey.WithDedicatedMac<*>.encrypt(
    data: ByteArray,
    authenticatedData: ByteArray? = null,
    dedicatedMacAuthTagCalculation: DedicatedMacInputCalculation = DefaultDedicatedMacInputCalculation,
): KmmResult<SealedBox<Authenticated.WithDedicatedMac<*, *>, *,
        SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, *>, *>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        dedicatedMacKey,
        null,
        authenticatedData,
        dedicatedMacAuthTagCalculation
    ).encrypt(data)
}

@JvmName("encryptAuthenticatedWithDedicatedMacAndIV")
fun SymmetricKey.WithDedicatedMac<IV.Required>.encrypt(
    data: ByteArray,
    authenticatedData: ByteArray? = null,
    dedicatedMacAuthTagCalculation: DedicatedMacInputCalculation = DefaultDedicatedMacInputCalculation,
): KmmResult<SealedBox.WithIV<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>,
        SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>>> =
    (this as SymmetricKey.WithDedicatedMac<*>).encrypt(
        data,
        authenticatedData,
        dedicatedMacAuthTagCalculation
    ) as KmmResult<SealedBox.WithIV<Authenticated.WithDedicatedMac<*, IV.Required>, SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>>>

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
     * Encrypts [data] and returns a [at.asitplus.signum.indispensable.symmetric.Ciphertext] matching the algorithm type that was used to create this [Encryptor] object.
     * E.g., an authenticated encryption algorithm causes this function to return a [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated].
     */
    fun encrypt(data: ByteArray): C = if (algorithm.cipher is Authenticated.WithDedicatedMac<*, *>) {
        val aMac = algorithm.cipher as Authenticated.WithDedicatedMac<*, *>
        aMac.innerCipher
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

        (if (algorithm.iv is IV.Required) {
            (algorithm as SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>).sealedBox(
                (encrypted as SealedBox.WithIV<*, *>).iv,
                ciphertext.encryptedData,
                ciphertext.authTag,
                ciphertext.authenticatedData
            )
        } else (algorithm as SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, IV.Without>).sealedBox(
            ciphertext.encryptedData,
            ciphertext.authTag,
            ciphertext.authenticatedData
        )) as C

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

/**
 * Attempts to decrypt this ciphertext (which also holds IV, and in case of an authenticated ciphertext, AAD and auth tag) using the provided [key].
 * This is the function you typically want to use.
 */
fun SealedBox.WithIV<*, SymmetricEncryptionAlgorithm<*, IV.Required>>.decrypt(key: SymmetricKey<*, IV.Required>): KmmResult<ByteArray> =
    catching {
        require(ciphertext.algorithm == key.algorithm) { "Somebody likes cursed casts!" }
        if (ciphertext is Ciphertext.Authenticated.WithDedicatedMac) {
            (this as SealedBox<Authenticated.WithDedicatedMac<*, *>, *, SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, *>, *>>).decrypt(
                key.secretKey, (key as SymmetricKey.WithDedicatedMac<*>).dedicatedMacKey
            )
        }
        decrypt(key.secretKey).getOrThrow()
    }

/**
 * Attempts to decrypt this ciphertext (which also holds IV, and in case of an authenticated ciphertext, AAD and auth tag) using the provided [key].
 * This is the function you typically want to use.
 */
@JvmName("decryptAuthenticatedWithIV")
fun SealedBox.WithIV<CipherKind.Authenticated, SymmetricEncryptionAlgorithm<Authenticated, IV.Required>>.decrypt(
    key: SymmetricKey<*, IV.Required>
): KmmResult<ByteArray> = catching {
    require(ciphertext.algorithm == key.algorithm) { "Somebody likes cursed casts!" }
    if (ciphertext is Ciphertext.Authenticated.WithDedicatedMac) {
        (this as SealedBox<Authenticated.WithDedicatedMac<*, *>, *, SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, *>, *>>).decrypt(
            key.secretKey, (key as SymmetricKey.WithDedicatedMac<*>).dedicatedMacKey
        )
    }
    decrypt(key.secretKey).getOrThrow()
}

/**
 * Attempts to decrypt this ciphertext using the provided raw [secretKey].
 */
@JvmName("decryptAny")
fun SealedBox<*, *, *>.decrypt(secretKey: ByteArray): KmmResult<ByteArray> =
    catching {
        require(secretKey.size.toUInt() == ciphertext.algorithm.keySize.bytes) { "Key must be exactly ${ciphertext.algorithm.keySize} bits long" }
        when (ciphertext) {
            is Ciphertext.Authenticated.Integrated -> (this as SealedBox<Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<Authenticated.Integrated, *>>).doDecrypt(
                secretKey
            )

            is Ciphertext.Unauthenticated -> (this as SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>>).doDecrypt(
                secretKey
            )

            is Ciphertext.Authenticated.WithDedicatedMac -> (this as SealedBox<Authenticated.WithDedicatedMac<*, *>, *, SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, *>, *>>).decrypt(
                secretKey
            ).getOrThrow()
        }
    }

fun <A : CipherKind, I : IV> SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>>.decrypt(key: SymmetricKey<A, I>): KmmResult<ByteArray> =
    catching {
        require(this.ciphertext.algorithm == key.algorithm) { "Somebody likes cursed casts!" }
        (this as SealedBox<*, *, *>).decrypt(key.secretKey).getOrThrow()
    }

@JvmName("decryptAuthenticatedWithIVandDedicatdMAC")
fun SealedBox.WithIV<CipherKind.Authenticated.WithDedicatedMac<*, IV.Required>, SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, IV.Required>, IV.Required>>.decrypt(
    key: SymmetricKey.WithDedicatedMac<*>,
    dedicatedMacInputCalculation: DedicatedMacInputCalculation = DefaultDedicatedMacInputCalculation
) =
    (this as SealedBox<Authenticated.WithDedicatedMac<*, *>, *, SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, *>, *>>).decrypt(
        key.secretKey, key.dedicatedMacKey, dedicatedMacInputCalculation
    )

/**
 * Attempts to decrypt this ciphertext using the provided raw [secretKey].
 * If no [macKey] is provided, [secretKey] will be used as MAC key.
 * [dedicatedMacInputCalculation] can be used to override the [DefaultDedicatedMacInputCalculation] used to compute MAC input.
 */
fun SealedBox<Authenticated.WithDedicatedMac<*, *>, *, SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, *>, *>>.decrypt(
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
        (if (this is SealedBox.WithIV<*, *>) (innerCipher as SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Required>).sealedBox(
            this.iv,
            innerCipherText.encryptedData
        ) else (innerCipher as SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Without>).sealedBox(
            innerCipherText.encryptedData
        )) as SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>>
    box.doDecrypt(secretKey)
}


expect internal fun SealedBox<Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<Authenticated.Integrated, *>>.doDecrypt(
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

