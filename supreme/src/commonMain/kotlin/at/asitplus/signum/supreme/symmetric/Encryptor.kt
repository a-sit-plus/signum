package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.internals.ImplementationError
import at.asitplus.signum.supreme.mac.mac
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

/**
 * Additional abstraction layer atop [PlatformCipher]. Currently, this is used to
 * * check parameters (nonce length, key length, …)
 * * implement AES-CBC-HMAC using AES-CBC as basic building block
 *
 * Given we have ECB, we would use it to implement more modes of operation.
 */
internal sealed interface Encryptor<out E : SymmetricEncryptionAlgorithm<*, *>> {
    //suspending init needs faux-ctor
    companion object {
        suspend operator fun <I : NonceTrait, E : SymmetricEncryptionAlgorithm<*, I>> invoke(
            algorithm: E,
            key: ByteArray,
            macKey: ByteArray?,
            @OptIn(HazardousMaterials::class)
            nonce: ByteArray? = if (algorithm.requiresNonce()) algorithm.randomNonce() else null,
            aad: ByteArray?,
        ): Encryptor<E> {
            if (algorithm.requiresNonce()) {
                require(nonce != null) { "$algorithm requires a nonce" }
                require(nonce.size.toUInt() == algorithm.nonceSize.bytes) { "$algorithm IV must be exactly ${algorithm.nonceSize} bits long" }
            }
            require(key.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
            return if (algorithm.hasDedicatedMac()) Mac(
                initCipher(PlatformCipher.Mode.ENCRYPT, algorithm.innerCipher, key, nonce, aad),
                algorithm,
                macKey ?: throw ImplementationError("AES-CBC-HMAC MAC key is null")
            )
            else Integrated(initCipher(PlatformCipher.Mode.ENCRYPT, algorithm, key, nonce, aad))
        }
    }


    /**
     * Encrypts [data] and returns a [at.asitplus.signum.indispensable.symmetric.Ciphertext] matching the algorithm type that was used to create this [Encryptor] object.
     * E.g., an authenticated encryption algorithm causes this function to return a [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated].
     */
    suspend fun encrypt(data: ByteArray): SealedBox<E>

    class Mac<out I : NonceTrait, out E : SymmetricEncryptionAlgorithm.EncryptThenMAC<I>>(
        val platformCipher: PlatformCipher<SymmetricEncryptionAlgorithm<*, I>>,
        val algorithm: E,
        /*this needs to go here, because we implement boltend-on AEAD in this file here, not in PlatformCipher*/
        private val macKey: ByteArray,
    ) : Encryptor<E> {
        @OptIn(ExperimentalContracts::class)
        fun requiresNonce(): Boolean {
            contract {
                returns(true) implies (this@Mac is Mac<NonceTrait.Required, SymmetricEncryptionAlgorithm.EncryptThenMAC<NonceTrait.Required>>)
                returns(false) implies (this@Mac is Mac<NonceTrait.Without, SymmetricEncryptionAlgorithm.EncryptThenMAC<NonceTrait.Without>>)
            }
            return algorithm.requiresNonce()
        }

        suspend fun authTag(encrypted: SealedBox<*>, nonce: ByteArray): ByteArray {
            val macInputCalculation = algorithm.macInputCalculation
            val hmacInput: ByteArray = algorithm.macInputCalculation(
                encrypted.encryptedData,
                nonce,
                platformCipher.aad ?: byteArrayOf()
            )

            val outputTransform = algorithm.macAuthTagTransform
            return algorithm.outputTransform(algorithm.mac.mac(macKey, hmacInput).getOrThrow())
        }

        override suspend fun encrypt(data: ByteArray): SealedBox<E> =
            //Our own, flexible construction to make any unauthenticated cipher into an authenticated cipher
            when {
                !algorithm.innerCipher.requiresNonce() -> throw ImplementationError("AES-CBC-HMAC Nonce inconsistency")
                requiresNonce() -> {
                    val encrypted = platformCipher.doEncrypt(data)
                    algorithm.sealedBox.withNonce(encrypted.nonce).from(
                        encrypted.encryptedData,
                        authTag(encrypted, encrypted.nonce)
                    )
                }

                else -> {
                    val encrypted = platformCipher.doEncrypt(data)
                    algorithm.sealedBox.from(encrypted.encryptedData, authTag(encrypted, byteArrayOf()))
                }
            }.getOrThrow()
    }

    private class Integrated<out E : SymmetricEncryptionAlgorithm.Integrated<*>>(
        val platformCipher: PlatformCipher<E>,
    ) : Encryptor<E> {
        override suspend fun encrypt(data: ByteArray): SealedBox<E> = platformCipher.doEncrypt(data)
    }
}

/**
 * Platform cipher abstraction.
 */
internal interface PlatformCipher<out E : SymmetricEncryptionAlgorithm<*, *>> {
    /**
     * We could do away with the encrypt/decrypt state and add subclassses, etc. but then we'd just have double the glue
     * code, because every platform cipher works that way.
     */
    val mode: Mode
    val algorithm: E
    val key: ByteArray
    val nonce: ByteArray?
    val aad: ByteArray?
    //for later use, we could add val oneshot:Boolean =true here and add update() and doFinal()

    suspend fun doDecrypt(data: ByteArray, authTag: ByteArray?): ByteArray

    suspend fun doEncrypt(data: ByteArray): SealedBox<E>

    enum class Mode {
        ENCRYPT,
        DECRYPT,
        ;
    }
}

internal expect suspend fun <E : SymmetricEncryptionAlgorithm<*, *>> initCipher(
    mode: PlatformCipher.Mode,
    algorithm: E,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): PlatformCipher<E>
