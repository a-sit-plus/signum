package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.ImplementationError
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.AuthCapability.Authenticated
import at.asitplus.signum.supreme.mac.mac


internal class Encryptor<A : AuthCapability<out K>, I : NonceTrait, out K : KeyType> internal constructor(
    private val algorithm: SymmetricEncryptionAlgorithm<A, I, K>,
    private val key: ByteArray,
    private val macKey: ByteArray?,
    @OptIn(HazardousMaterials::class)
    private val nonce: ByteArray? = if (algorithm.requiresNonce()) algorithm.randomNonce() else null,
    private val aad: ByteArray?,
) {

    init {


        if (algorithm.nonceTrait is NonceTrait.Required) nonce?.let {
            require(it.size.toUInt() == (algorithm.nonceTrait as NonceTrait.Required).length.bytes) { "IV must be exactly ${(algorithm.nonceTrait as NonceTrait.Required).length} bits long" }
        }
        require(key.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    }

    /**
     * Encrypts [data] and returns a [at.asitplus.signum.indispensable.symmetric.Ciphertext] matching the algorithm type that was used to create this [Encryptor] object.
     * E.g., an authenticated encryption algorithm causes this function to return a [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated].
     */
    internal suspend fun encrypt(data: ByteArray): SealedBox<A, I, out K> {
        //Our own, flexible construction to make any unauthenticated cipher into an authenticated cipher
        if (algorithm.hasDedicatedMac()) {
            val aMac = algorithm.authCapability
            aMac.innerCipher
            val innerCipher =
                initCipher(
                    PlatformCipher.Mode.ENCRYPT,
                    aMac.innerCipher,
                    key,
                    nonce,
                    aad
                )

            if (!aMac.innerCipher.requiresNonce()) throw ImplementationError("AES-CBC-HMAC Nonce inconsistency")
            if (macKey == null) throw ImplementationError("AES-CBC-HMAC MAC key is null")

            val encrypted = innerCipher.doEncrypt(data)
            val macInputCalculation = aMac.dedicatedMacInputCalculation
            val hmacInput: ByteArray =
                aMac.mac.macInputCalculation(
                    encrypted.encryptedData,
                    innerCipher.nonce ?: byteArrayOf(),
                    aad ?: byteArrayOf()
                )

            val outputTransform = aMac.dedicatedMacAuthTagTransform
            val authTag = aMac.outputTransform(aMac.mac.mac(macKey, hmacInput).getOrThrow())

            @Suppress("UNCHECKED_CAST")
            return (if (algorithm.requiresNonce()) {
                (algorithm).sealedBoxFrom(
                    (encrypted as SealedBox.WithNonce<*, *>).nonce,
                    encrypted.encryptedData,
                    authTag
                )
            } else (algorithm).sealedBoxFrom(
                encrypted.encryptedData,
                authTag
            )).getOrThrow() as SealedBox<A, I, K>

        } else @Suppress("UNCHECKED_CAST") return initCipher(
            PlatformCipher.Mode.ENCRYPT,
            algorithm,
            key,
            nonce,
            aad
        ).doEncrypt(data) as SealedBox<A, I, out K>
    }
}

/**
 * Platform cipher abstraction.
 */
internal interface PlatformCipher<A : AuthCapability<out K>, I : NonceTrait, K : KeyType> {
    /**
     * We could do away with the encrypt/decrypt state and add subclassses, etc. but then we'd just have double the glue
     * code, because every platform cipher works that way.
     */
    val mode: Mode
    val algorithm: SymmetricEncryptionAlgorithm<A, I, K>
    val key: ByteArray
    val nonce: ByteArray?
    val aad: ByteArray?
    //for later use, we could add val oneshot:Boolean =true here and add update() and doFinal()

    abstract suspend fun doDecrypt(data: ByteArray, authTag: ByteArray?): ByteArray

    abstract suspend fun doEncrypt(data: ByteArray): SealedBox<A, I, out K>

    enum class Mode {
        ENCRYPT,
        DECRYPT,
        ;
    }
}


internal suspend fun SealedBox<Authenticated.Integrated, *, out KeyType.Integrated>.doDecryptAEAD(
    secretKey: ByteArray,
    authenticatedData: ByteArray
): ByteArray {
    val authTag = if (isAuthenticated()) authTag else null
    val nonce = if (hasNonce()) nonce else null

    return initCipher(PlatformCipher.Mode.DECRYPT, algorithm, secretKey, nonce, authenticatedData).doDecrypt(
        encryptedData,
        authTag
    )
}

internal suspend fun SealedBox<AuthCapability.Unauthenticated, *, out KeyType.Integrated>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    val nonce = if (hasNonce()) nonce else null
    return initCipher(PlatformCipher.Mode.DECRYPT, algorithm, secretKey, nonce, null).doDecrypt(encryptedData, null)
}

internal expect suspend fun <A : AuthCapability<out K>, I : NonceTrait, K : KeyType> initCipher(
    mode: PlatformCipher.Mode,
    algorithm: SymmetricEncryptionAlgorithm<A, I, K>,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): PlatformCipher<A, I, K>


internal suspend fun SealedBox<*, *, *>.initDecrypt(key: ByteArray, aad: ByteArray?): PlatformCipher<*, *, *> =
    initCipher(PlatformCipher.Mode.DECRYPT, algorithm, key, if (hasNonce()) nonce else null, aad)