package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.AuthCapability.Authenticated
import at.asitplus.signum.supreme.mac.mac


internal class Encryptor<A : AuthCapability<out K>, I : WithNonce, out K : KeyType> internal constructor(
    private val algorithm: SymmetricEncryptionAlgorithm<A, I, K>,
    private val key: ByteArray,
    private val macKey: ByteArray?,
    private val iv: ByteArray?,
    private val aad: ByteArray?,
) {

    init {
        if (algorithm.withNonce is WithNonce.Yes) iv?.let {
            require(it.size.toUInt() == (algorithm.withNonce as WithNonce.Yes).length.bytes) { "IV must be exactly ${(algorithm.withNonce as WithNonce.Yes).length} bits long" }
        }
        require(key.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    }


    private val platformCipher: CipherParam<*, A, out K> = initCipher<Any, A, I, K>(algorithm, key, iv, aad)

    /**
     * Encrypts [data] and returns a [at.asitplus.signum.indispensable.symmetric.Ciphertext] matching the algorithm type that was used to create this [Encryptor] object.
     * E.g., an authenticated encryption algorithm causes this function to return a [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated].
     */
    internal fun encrypt(data: ByteArray): SealedBox<A, I, out K> = (
            //Our own, flexible construction to make any unauthenticated cipher into an authenticated cipher
            if (algorithm.hasDedicatedMac()) {
                val aMac = algorithm.authCapability
                aMac.innerCipher
                val innerCipher =
                    initCipher<Any, AuthCapability.Unauthenticated, I, KeyType.Integrated>(
                        aMac.innerCipher as SymmetricEncryptionAlgorithm.Unauthenticated<I>,
                        key,
                        iv,
                        aad
                    )

                if (aMac.innerCipher.requiresNonce())
                    require(innerCipher.nonce != null) { "Nonce implementation error. Report this bug!" }
                require(macKey != null) { "MAC key implementation error. Report this bug!" }
                val encrypted = innerCipher.doEncrypt<AuthCapability.Unauthenticated, I, KeyType.Integrated>(data)
                val macInputCalculation = aMac.dedicatedMacInputCalculation
                val hmacInput: ByteArray =
                    aMac.mac.macInputCalculation(
                        encrypted.encryptedData,
                        innerCipher.nonce ?: byteArrayOf(),
                        aad ?: byteArrayOf()
                    )

                val authTag = aMac.mac.mac(macKey, hmacInput).getOrThrow()

                (if (algorithm.requiresNonce()) {
                    (algorithm).sealedBoxFrom(
                        (encrypted as SealedBox.WithNonce<*, *>).nonce,
                        encrypted.encryptedData,
                        authTag,
                        aad
                    )
                } else (algorithm).sealedBoxFrom(
                    encrypted.encryptedData,
                    authTag,
                    aad
                )).getOrThrow() as SealedBox<A, I, K>

            } else platformCipher.doEncrypt(data))


}

internal class CipherParam<T, A : AuthCapability<K>, K : KeyType>(
    val alg: SymmetricEncryptionAlgorithm<A, *, K>,
    val platformData: T,
    val nonce: ByteArray?,
    val aad: ByteArray?
)


expect internal fun SealedBox<Authenticated.Integrated, *, out KeyType.Integrated>.doDecrypt(
    secretKey: ByteArray
): ByteArray

expect internal fun SealedBox<AuthCapability.Unauthenticated, *, out KeyType.Integrated>.doDecrypt(
    secretKey: ByteArray
): ByteArray


internal expect fun <T, A : AuthCapability<out K>, I : WithNonce, K : KeyType> initCipher(
    algorithm: SymmetricEncryptionAlgorithm<A, I, K>,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A, out K>

internal expect fun <A : AuthCapability<out K>, I : WithNonce, K : KeyType> CipherParam<*, A, out K>.doEncrypt(data: ByteArray): SealedBox<A, I, out K>
