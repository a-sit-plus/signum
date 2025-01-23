package at.asitplus.signum.supreme.symmetric

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.CipherKind.Authenticated
import at.asitplus.signum.indispensable.symmetric.SymmetricKey.WithDedicatedMac
import at.asitplus.signum.supreme.mac.mac
import org.kotlincrypto.SecureRandom
import kotlin.jvm.JvmName

internal val secureRandom = SecureRandom()

@HazardousMaterials
@JvmName("encryptWithIV")
fun <A : CipherKind> SymmetricKey<A, IV.Required>.encrypt(
    iv: ByteArray,
    data: ByteArray
): KmmResult<SealedBox.WithIV<A, SymmetricEncryptionAlgorithm<A, IV.Required>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
        iv,
        null,
    ).encrypt(data) as SealedBox.WithIV<A, SymmetricEncryptionAlgorithm<A, IV.Required>>
}

@JvmName("encryptWithAutoGenIV")
fun <A : CipherKind, I : IV> SymmetricKey<A, I>.encrypt(
    data: ByteArray
): KmmResult<SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
        null,
        null,
    ).encrypt(data) as SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>>
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
fun <A: CipherKind.Authenticated>SymmetricKey<A, IV.Required>.encrypt(
    iv: ByteArray,
    data: ByteArray,
    authenticatedData: ByteArray? = null
): KmmResult<SealedBox.WithIV<A, SymmetricEncryptionAlgorithm<A, IV.Required>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
        iv,
        authenticatedData,
    ).encrypt(data) as SealedBox.WithIV<A, SymmetricEncryptionAlgorithm<A, IV.Required>>
}

/**
 * Encrypts [data] and automagically generates a fresh IV if required by the cipher.
 * This is the method you want to use, as it generates a fresh IV, if the underlying cipher requires an IV.
 * * [authenticatedData] = _Additional Authenticated Data_
 *
 * It is safe to discard the reference to [authenticatedData], as both IV and AAD will be added to any [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated] resulting from an encryption.
 *
 * @return [KmmResult.success] containing a [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated] if valid parameters were provided or [KmmResult.failure] in case of
 * invalid parameters (e.g., key or IV length)
 */
@JvmName("encryptAuthenticated")
fun <A: CipherKind.Authenticated, I:IV>SymmetricKey<A, I>.encrypt(
    data: ByteArray,
    authenticatedData: ByteArray? = null
): KmmResult<SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>>> = catching {
    Encryptor(
        algorithm,
        secretKey,
        if (this is WithDedicatedMac) dedicatedMacKey else secretKey,
        null,
        authenticatedData,
    ).encrypt(data)
}


internal class Encryptor<A : CipherKind, E : SymmetricEncryptionAlgorithm<A, *>, C : SealedBox<A, *, E>> internal constructor(
    private val algorithm: E,
    private val key: ByteArray,
    private val macKey: ByteArray?,
    private val iv: ByteArray?,
    private val aad: ByteArray?,
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
        val macInputCalculation = aMac.dedicatedMacInputCalculation
        val hmacInput: ByteArray =
            aMac.mac.macInputCalculation(
                encrypted.ciphertext.encryptedData,
                innerCipher.iv,
                (aad ?: byteArrayOf())
            )

        val maced = aMac.mac.mac(macKey, hmacInput).getOrThrow()

        val ciphertext = Ciphertext.Authenticated(
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
fun <A: CipherKind>SealedBox<in A,IV.Required, SymmetricEncryptionAlgorithm<A, IV.Required>>.decrypt(key: SymmetricKey< in A, IV.Required>): KmmResult<ByteArray> =
    catching {
        require(ciphertext.algorithm == key.algorithm) { "Somebody likes cursed casts!" }
        when (ciphertext.algorithm.cipher as CipherKind) {
            is Authenticated.Integrated -> (this as SealedBox<Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>>).decryptInternal(
                key.secretKey
            )

            is Authenticated.WithDedicatedMac<*, *> -> {
                key as SymmetricKey.WithDedicatedMac
                (this as SealedBox<Authenticated.WithDedicatedMac<*, *>, *, SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, *>, *>>).doDecrypt(
                    key.secretKey, key.dedicatedMacKey
                )
            }

            is CipherKind.Unauthenticated -> (this as SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>>).decryptInternal(
                key.secretKey
            )
        }
    }

@JvmName("decryptRawAuthenticated")
private fun SealedBox<Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>>.decryptInternal(
    secretKey: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == ciphertext.algorithm.keySize.bytes) { "Key must be exactly ${ciphertext.algorithm.keySize} bits long" }
    return doDecrypt(secretKey)
}

@JvmName("decryptRaw")
private fun SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>>.decryptInternal(
    secretKey: ByteArray
): ByteArray {
    require(secretKey.size.toUInt() == ciphertext.algorithm.keySize.bytes) { "Key must be exactly ${ciphertext.algorithm.keySize} bits long" }
    return doDecrypt(secretKey)
}

/**
 * Attempts to decrypt this ciphertext using the provided raw [secretKey].
 * If no [macKey] is provided, [secretKey] will be used as MAC key.
 * [dedicatedMacInputCalculation] can be used to override the [DefaultDedicatedMacInputCalculation] used to compute MAC input.
 */
private fun SealedBox<Authenticated.WithDedicatedMac<*, *>, *, SymmetricEncryptionAlgorithm<Authenticated.WithDedicatedMac<*, *>, *>>.doDecrypt(
    secretKey: ByteArray,
    macKey: ByteArray = secretKey,
): ByteArray {
    val iv: ByteArray? = if (this is SealedBox.WithIV<*, *>) iv else null
    val aad = (ciphertext as Ciphertext.Authenticated).authenticatedData
    val authTag = (ciphertext as Ciphertext.Authenticated).authTag

    val algorithm = ciphertext.algorithm
    val innerCipher = ciphertext.algorithm.cipher.innerCipher
    val mac = algorithm.cipher.mac
    val dedicatedMacInputCalculation = algorithm.cipher.dedicatedMacInputCalculation
    val hmacInput = mac.dedicatedMacInputCalculation(ciphertext.encryptedData, iv, aad)

    if (!(mac.mac(macKey, hmacInput).getOrThrow().contentEquals(authTag)))
        throw IllegalArgumentException("Auth Tag mismatch!")

    val innerCipherText: Ciphertext.Unauthenticated = Ciphertext.Unauthenticated(innerCipher, ciphertext.encryptedData)
    val box: SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>> =
        (if (this is SealedBox.WithIV<*, *>) (innerCipher as SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Required>).sealedBox(
            this.iv,
            innerCipherText.encryptedData
        ) else (innerCipher as SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, IV.Without>).sealedBox(
            innerCipherText.encryptedData
        )) as SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>>
    return box.doDecrypt(secretKey)
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

