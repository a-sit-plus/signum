package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.AECapability.Authenticated
import at.asitplus.signum.supreme.mac.mac


internal class Encryptor<A : AECapability<*>, E : SymmetricEncryptionAlgorithm<A, *>, C : SealedBox<A, *, E>> internal constructor(
    private val algorithm: E,
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


    private val platformCipher: CipherParam<*, A> = initCipher<Any, A, E>(algorithm, key, iv, aad)

    /**
     * Encrypts [data] and returns a [at.asitplus.signum.indispensable.symmetric.Ciphertext] matching the algorithm type that was used to create this [Encryptor] object.
     * E.g., an authenticated encryption algorithm causes this function to return a [at.asitplus.signum.indispensable.symmetric.Ciphertext.Authenticated].
     */
    fun encrypt(data: ByteArray): C = if (algorithm.authCapability is Authenticated.WithDedicatedMac<*, *>) {
        val aMac = algorithm.authCapability as Authenticated.WithDedicatedMac<*, *>
        aMac.innerCipher
        val innerCipher =
            initCipher<Any, AECapability.Unauthenticated, SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, *>>(
                aMac.innerCipher,
                key,
                iv,
                aad
            )

        require(innerCipher.nonce != null) { "IV implementation error. Report this bug!" }
        require(macKey != null) { "MAC key implementation error. Report this bug!" }
        val encrypted = innerCipher.doEncrypt<AECapability.Unauthenticated, Nonce>(data)
        val macInputCalculation = aMac.dedicatedMacInputCalculation
        val hmacInput: ByteArray =
            aMac.mac.macInputCalculation(
                encrypted.encryptedData,
                innerCipher.nonce,
                aad?:byteArrayOf()
            )

        val authTag = aMac.mac.mac(macKey, hmacInput).getOrThrow()

        (if (algorithm.nonce is Nonce.Required) {
            (algorithm as SymmetricEncryptionAlgorithm<AECapability.Authenticated.WithDedicatedMac<*, Nonce.Required>, Nonce.Required>).sealedBox(
                (encrypted as SealedBox.WithNonce<*, *>).nonce,
                encrypted.encryptedData,
                authTag,
                aad
            )
        } else (algorithm as SymmetricEncryptionAlgorithm<AECapability.Authenticated.WithDedicatedMac<*, Nonce.Required>, Nonce.Without>).sealedBox(
            encrypted.encryptedData,
            authTag,
            aad
        )) as C

    } else platformCipher.doEncrypt<A, Nonce>(data) as C


}

internal class CipherParam<T, A : AECapability<*>>(
    val alg: SymmetricEncryptionAlgorithm<A, *>,
    val platformData: T,
    val nonce: ByteArray?,
    val aad: ByteArray?
)


expect internal fun SealedBox<Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<Authenticated.Integrated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray

expect internal fun SealedBox<AECapability.Unauthenticated, *, SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray


internal expect fun <T, A : AECapability<*>, E : SymmetricEncryptionAlgorithm<A, *>> initCipher(
    algorithm: E,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A>

internal expect fun <A : AECapability<*>, I : Nonce> CipherParam<*, A>.doEncrypt(data: ByteArray): SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>>
