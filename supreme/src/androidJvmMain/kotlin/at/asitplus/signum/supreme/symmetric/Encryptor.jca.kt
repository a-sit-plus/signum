package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import javax.crypto.Cipher

internal actual suspend fun <E: SymmetricEncryptionAlgorithm<*, *>> initCipher(
    mode: PlatformCipher.Mode,
    algorithm: E,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): PlatformCipher<E> = JcaPlatformCipher(mode, algorithm, key, nonce, aad)

internal class JcaPlatformCipher<out E: SymmetricEncryptionAlgorithm<*, *>>(
    override val mode: PlatformCipher.Mode,
    override val algorithm: E,
    override val key: ByteArray,
    override val nonce: ByteArray?,
    override val aad: ByteArray?,
) : PlatformCipher<E> {


    private val cipher: Cipher =
        when {
            algorithm.requiresNonce() -> {
            require(nonce != null) { "Nonce is required for ${algorithm.name}!" }

                @Suppress("UNCHECKED_CAST")
                when (algorithm) {
                    is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> ChaChaJVM.initCipher(mode, key, nonce, aad)
                    is SymmetricEncryptionAlgorithm.AES<*, *> -> AESJCA.initCipher(mode, algorithm, key, nonce, aad)
                }
            }

            else -> {
                @OptIn(HazardousMaterials::class)
                if ((algorithm !is SymmetricEncryptionAlgorithm.AES.ECB) && (algorithm !is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394))
                    TODO("$algorithm is UNSUPPORTED")
                AESJCA.initCipher(mode, algorithm, key, nonce, aad)
            }
        }

    override suspend fun doEncrypt(data: ByteArray): SealedBox<E> {
        require(mode == PlatformCipher.Mode.ENCRYPT) { "Cipher not in ENCRYPT mode!" }
        val jcaCiphertext = cipher.doFinal(data)
        //JCA simply concatenates ciphertext and authtag, so we need to split

        //align android and JVM
        if(algorithm is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394){
            require((data.size >= 16) && (data.size % 8 == 0)) {"data length not compliant to RFC 3394. should be: (data.size >= 16) && (data.size % 8 == 0), is: ${data.size}"}
        }

        val (ciphertext, authTag) = when (algorithm.isAuthenticated()) {
            true -> {
                val tagSize = algorithm.authTagSize.bytes.toInt()
                Pair(jcaCiphertext.dropLast(tagSize).toByteArray(), jcaCiphertext.takeLast(tagSize).toByteArray())
            }
            false -> Pair(jcaCiphertext, null)
        }

        @Suppress("UNCHECKED_CAST")
        return when {
            algorithm.requiresNonce() -> when {
                algorithm.isAuthenticated() -> {
                    algorithm.sealedBox.withNonce(nonce!!).from(ciphertext, authTag!!)
                }

                else -> algorithm.sealedBox.withNonce(nonce!!).from(ciphertext)
            }

            algorithm.isAuthenticated() -> algorithm.sealedBox.from(ciphertext, authTag!!)
            else -> algorithm.sealedBox.from(ciphertext)
        }.getOrThrow()
    }

    override suspend fun doDecrypt(data: ByteArray, authTag: ByteArray?): ByteArray {
        require(mode == PlatformCipher.Mode.DECRYPT) { "Cipher not in DECRYPT mode!" }
        return when (algorithm.isAuthenticated()) {
            true -> cipher.doFinal(data + authTag!!)
            false -> cipher.doFinal(data)
        }
    }
}

internal val PlatformCipher.Mode.jcaCipherMode
    get() = when (this) {
        PlatformCipher.Mode.ENCRYPT -> Cipher.ENCRYPT_MODE
        PlatformCipher.Mode.DECRYPT -> Cipher.DECRYPT_MODE
    }

