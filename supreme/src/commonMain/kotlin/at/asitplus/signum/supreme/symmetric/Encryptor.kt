package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.AuthType.Authenticated
import at.asitplus.signum.supreme.mac.mac


internal class Encryptor<A : AuthType<K>, I : Nonce, K : KeyType> internal constructor(
    private val algorithm: SymmetricEncryptionAlgorithm<A, I, K>,
    private val key: ByteArray,
    private val macKey: ByteArray?,
    private val iv: ByteArray?,
    private val aad: ByteArray?,
) {

    init {
        if (algorithm.nonce is Nonce.Required) iv?.let {
            require(it.size.toUInt() == (algorithm.nonce as Nonce.Required).length.bytes) { "IV must be exactly ${(algorithm.nonce as Nonce.Required).length} bits long" }
        }
        require(key.size.toUInt() == algorithm.keySize.bytes) { "Key must be exactly ${algorithm.keySize} bits long" }
    }


    private val platformCipher: CipherParam<*, A,K> = initCipher<Any, A, I, K>(algorithm, key, iv, aad)

    /**
     * Encrypts [data] and returns a [at.asitplus.signum.indispensable.symmetric.Ciphertext] matching the algorithm type that was used to create this [Encryptor] object.
     * E.g., an authenticated encryption algorithm causes this function to return a [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated].
     */
    fun encrypt(data: ByteArray): SealedBox<A,I,K> = if (algorithm.authCapability is Authenticated.WithDedicatedMac<*, *>) {
        val aMac = algorithm.authCapability as Authenticated.WithDedicatedMac<*, *>
        aMac.innerCipher
        val innerCipher =
            initCipher<Any, AuthType.Unauthenticated, I, KeyType.Integrated>(
                aMac.innerCipher,
                key,
                iv,
                aad
            )

        require(innerCipher.nonce != null) { "IV implementation error. Report this bug!" }
        require(macKey != null) { "MAC key implementation error. Report this bug!" }
        val encrypted = innerCipher.doEncrypt<AuthType.Unauthenticated, Nonce>(data)
        val macInputCalculation = aMac.dedicatedMacInputCalculation
        val hmacInput: ByteArray =
            aMac.mac.macInputCalculation(
                encrypted.encryptedData,
                innerCipher.nonce,
                aad ?: byteArrayOf()
            )

        val authTag = aMac.mac.mac(macKey, hmacInput).getOrThrow()

        (if (algorithm.nonce is Nonce.Required) {
            (algorithm as SymmetricEncryptionAlgorithm<AuthType.Authenticated.WithDedicatedMac<*, Nonce.Required>, Nonce.Required>).sealedBox(
                (encrypted as SealedBox.WithNonce<*, *>).nonce,
                encrypted.encryptedData,
                authTag,
                aad
            )
        } else (algorithm as SymmetricEncryptionAlgorithm<AuthType.Authenticated.WithDedicatedMac<*, Nonce.Required>, Nonce.Without>).sealedBox(
            encrypted.encryptedData,
            authTag,
            aad
        )) as SealedBox<A,I,K>

    } else platformCipher.doEncrypt<A, Nonce>(data) as C


}

internal class CipherParam<T, A : AuthType<K>,K: KeyType>(
    val alg: SymmetricEncryptionAlgorithm<A, *,K>,
    val platformData: T,
    val nonce: ByteArray?,
    val aad: ByteArray?
)


expect internal fun SealedBox<Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<Authenticated.Integrated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray

expect internal fun SealedBox<AuthType.Unauthenticated, *, SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray


internal expect fun <T, A : AuthType<K>, I : Nonce, K : KeyType> initCipher(
    algorithm: SymmetricEncryptionAlgorithm<A, I, K>,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A>

internal expect fun <A : AuthType<*>, I : Nonce> CipherParam<*, A>.doEncrypt(data: ByteArray): SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>>
