package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import javax.crypto.Cipher

internal actual suspend fun <A : AuthCapability<out K>, I : NonceTrait, K : KeyType> initCipher(
    mode: PlatformCipher.Mode,
    algorithm: SymmetricEncryptionAlgorithm<A, I, K>,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): PlatformCipher<A, I, K> = JcaPlatformCipher(mode, algorithm, key, nonce, aad)

internal class JcaPlatformCipher<A : AuthCapability<out K>, I : NonceTrait, K : KeyType>(
    override val mode: PlatformCipher.Mode,
    override val algorithm: SymmetricEncryptionAlgorithm<A, I, K>,
    override val key: ByteArray,
    override val nonce: ByteArray?,
    override val aad: ByteArray?,
) : PlatformCipher<A, I, K> {


    internal val cipher: Cipher =
        when {
            algorithm.requiresNonce() -> {


                @Suppress("UNCHECKED_CAST")
                when (algorithm) {
                    is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> ChaChaJVM.initCipher(mode, key, nonce!!, aad)
                    is SymmetricEncryptionAlgorithm.AES<*, *, *> -> AESJCA.initCipher(mode, algorithm, key, nonce, aad)
                }
            }

            else -> {
                @OptIn(HazardousMaterials::class)
                if ((algorithm !is SymmetricEncryptionAlgorithm.AES.ECB) && (algorithm !is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394))
                    TODO("$algorithm is UNSUPPORTED")
                AESJCA.initCipher(mode, algorithm, key, nonce, aad)
            }
        }

    override suspend fun doEncrypt(data: ByteArray): SealedBox<A, I, out K> {
        require(mode == PlatformCipher.Mode.ENCRYPT) { "Cipher not in ENCRYPT mode!" }
        val jcaCiphertext = cipher.doFinal(data)
        //JCA simply concatenates ciphertext and authtag, so we need to split
        val ciphertext =
            if (algorithm.authCapability is AuthCapability.Authenticated<*>)
                jcaCiphertext.dropLast(((algorithm.authCapability as AuthCapability.Authenticated<*>).tagLength.bytes.toInt()).toInt())
                    .toByteArray()
            else jcaCiphertext
        val authTag =
            if (algorithm.authCapability is AuthCapability.Authenticated<*>)
                jcaCiphertext.takeLast(((algorithm.authCapability as AuthCapability.Authenticated<*>).tagLength.bytes.toInt()).toInt())
                    .toByteArray() else null

        @Suppress("UNCHECKED_CAST")
        return when {
            algorithm.requiresNonce() -> when {
                algorithm.isAuthenticated() -> {
                    (algorithm as SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<*>, NonceTrait.Required, *>)
                    algorithm.sealedBoxFrom(nonce!!, ciphertext, authTag!!)
                }

                else -> algorithm.sealedBoxFrom(nonce!!, ciphertext)
            }

            else -> when {
                algorithm.isAuthenticated() -> {
                    (algorithm as SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<*>, NonceTrait.Without, *>)
                    algorithm.sealedBoxFrom(ciphertext, authTag!!)
                }

                else -> algorithm.sealedBoxFrom(ciphertext)
            }

        }.getOrThrow() as SealedBox<A, I, out K>
    }

    override suspend fun doDecrypt(data: ByteArray, authTag: ByteArray?): ByteArray {
        require(mode == PlatformCipher.Mode.DECRYPT) { "Cipher not in DECRYPT mode!" }
        return when (algorithm.isAuthenticated()) {
            true -> cipher.doFinal(data + authTag!!)
            false -> cipher.doFinal(data)
        }
    }
}

val SymmetricEncryptionAlgorithm<*, *, *>.jcaName: String
    @OptIn(HazardousMaterials::class)
    get() = when (this) {
        is SymmetricEncryptionAlgorithm.AES.GCM -> "AES/GCM/NoPadding"
        is SymmetricEncryptionAlgorithm.AES.CBC<*, *> -> "AES/CBC/PKCS5Padding"
        is SymmetricEncryptionAlgorithm.AES.ECB -> "AES/ECB/PKCS5Padding"
        is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394 -> "AESWrap"
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> "ChaCha20-Poly1305"
        else -> TODO("$this is unsupported")
    }

val SymmetricEncryptionAlgorithm<*, *, *>.jcaKeySpec: String
    get() = when (this) {
        is SymmetricEncryptionAlgorithm.AES<*, *, *> -> "AES"
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> "ChaCha20"
        else -> TODO("$this keyspec is unsupported UNSUPPORTED")
    }

internal val PlatformCipher.Mode.jcaCipherMode
    get() = when (this) {
        PlatformCipher.Mode.ENCRYPT -> Cipher.ENCRYPT_MODE
        PlatformCipher.Mode.DECRYPT -> Cipher.DECRYPT_MODE
    }

