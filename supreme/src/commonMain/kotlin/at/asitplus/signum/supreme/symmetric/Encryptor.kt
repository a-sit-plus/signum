package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.internals.ImplementationError
import at.asitplus.signum.supreme.mac.mac

/**
 * Additional abstraction layer atop [PlatformCipher]. Currently, this is used to
 * * check parameters (nonce length, key length, …)
 * * implement AES-CBC-HMAC using AES-CBC as basic building block
 *
 * Given we have ECB, we would use it to implement more modes of operation.
 */
internal class Encryptor<A : AuthCapability<out K>, I : NonceTrait, K : KeyType> private constructor(
    private val platformCipher: PlatformCipher<*, *, *>,
    private val algorithm: SymmetricEncryptionAlgorithm<A, I, K>,
    /*this needs to go here, because we implement boltend-on AEAD in this file here, not in PlatformCipher*/
    private val macKey: ByteArray?,
) {

    //suspending init needs faux-ctor
    companion object {
        suspend operator fun <A : AuthCapability<out K>, I : NonceTrait, K : KeyType> invoke(
            algorithm: SymmetricEncryptionAlgorithm<A, I, K>,
            key: ByteArray,
            macKey: ByteArray?,
            @OptIn(HazardousMaterials::class)
            nonce: ByteArray? = if (algorithm.requiresNonce()) algorithm.randomNonce() else null,
            aad: ByteArray?,

            ): Encryptor<A, I, K> {
            if (algorithm.requiresNonce()) {
                require(nonce != null) { "$algorithm requires a nonce" }
                require(nonce.size.toUInt() == algorithm.nonceSize.bytes) { "$algorithm IV must be exactly ${algorithm.nonceSize} bits long" }
            }
            require(key.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
            val platformCipher = if (algorithm.hasDedicatedMac())
                initCipher(
                    PlatformCipher.Mode.ENCRYPT,
                    algorithm.innerCipher,
                    key,
                    nonce,
                    aad
                )
            else initCipher(
                PlatformCipher.Mode.ENCRYPT,
                algorithm,
                key,
                nonce,
                aad
            )
            return Encryptor<A, I, K>(platformCipher, algorithm, macKey)
        }
    }


    /**
     * Encrypts [data] and returns a [at.asitplus.signum.indispensable.symmetric.Ciphertext] matching the algorithm type that was used to create this [Encryptor] object.
     * E.g., an authenticated encryption algorithm causes this function to return a [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated].
     */
    internal suspend fun encrypt(data: ByteArray): SealedBox<A, I, out K> {
        //Our own, flexible construction to make any unauthenticated cipher into an authenticated cipher
        if (algorithm.hasDedicatedMac()) {

            if (!algorithm.innerCipher.requiresNonce()) throw ImplementationError("AES-CBC-HMAC Nonce inconsistency")
            if (macKey == null) throw ImplementationError("AES-CBC-HMAC MAC key is null")

            val encrypted = platformCipher.doEncrypt(data)
            val macInputCalculation = algorithm.macInputCalculation
            val hmacInput: ByteArray =
                algorithm.macInputCalculation(
                    encrypted.encryptedData,
                    if (algorithm.requiresNonce()) platformCipher.nonce!! /*make it fail hard if not present*/ else byteArrayOf(),
                    platformCipher.aad ?: byteArrayOf()
                )

            val outputTransform = algorithm.macAuthTagTransform
            val authTag = algorithm.outputTransform(algorithm.mac.mac(macKey, hmacInput).getOrThrow())

            @Suppress("UNCHECKED_CAST")
            return (
                    if (algorithm.requiresNonce()) {
                        algorithm.sealedBox.withNonce((encrypted as SealedBox.WithNonce<*, *>).nonce).from(
                            encrypted.encryptedData,
                            authTag
                        )
                    } else (algorithm as SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<*>, NonceTrait.Without, *>).sealedBox.from(
                        encrypted.encryptedData,
                        authTag
                    )
                    ).getOrThrow() as SealedBox<A, I, K>

        } else @Suppress("UNCHECKED_CAST") return platformCipher.doEncrypt(data) as SealedBox<A, I, out K>
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

    suspend fun doDecrypt(data: ByteArray, authTag: ByteArray?): ByteArray

    suspend fun doEncrypt(data: ByteArray): SealedBox<A, I, out K>

    enum class Mode {
        ENCRYPT,
        DECRYPT,
        ;
    }
}

internal expect suspend fun <A : AuthCapability<out K>, I : NonceTrait, K : KeyType> initCipher(
    mode: PlatformCipher.Mode,
    algorithm: SymmetricEncryptionAlgorithm<A, I, K>,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): PlatformCipher<A, I, K>
