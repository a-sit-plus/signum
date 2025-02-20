package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.AuthCapability.Authenticated
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal actual fun <T, A : AuthCapability<out K>, I : NonceTrait, K : KeyType> initCipher(
    algorithm: SymmetricEncryptionAlgorithm<A, I, K>,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): PlatformCipher<T, A, out K> = when {
    algorithm.requiresNonce() -> {
        @OptIn(HazardousMaterials::class)
        val nonce = nonce ?: algorithm.randomNonce()

        @Suppress("UNCHECKED_CAST")
        when (algorithm) {
            is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> ChaChaJVM.initCipher(key, nonce, aad)
            is SymmetricEncryptionAlgorithm.AES<*, *, *> -> AESJCA.initCipher(algorithm, key, nonce, aad)
        } as PlatformCipher<T, A, K>
    }

    else -> {
        @OptIn(HazardousMaterials::class)
        if ((algorithm !is SymmetricEncryptionAlgorithm.AES.ECB) && (algorithm !is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394))
            TODO("$algorithm is UNSUPPORTED")

        AESJCA.initCipher(algorithm, key, nonce, aad) as PlatformCipher<T, A, K>
    }
}

internal actual fun <A : AuthCapability<out K>, I : NonceTrait, K : KeyType> PlatformCipher<*, A, out K>.doEncrypt(data: ByteArray): SealedBox<A, I, out K> {
    @Suppress("UNCHECKED_CAST") (this as PlatformCipher<Cipher, A, K>)
    val jcaCiphertext = platformData.doFinal(data)

    //JCA simply concatenates ciphertext and authtag, so we need to split
    val ciphertext =
        if (alg.authCapability is AuthCapability.Authenticated<*>)
            jcaCiphertext.dropLast(((alg.authCapability as AuthCapability.Authenticated<*>).tagLength.bytes.toInt()).toInt())
                .toByteArray()
        else jcaCiphertext
    val authTag =
        if (alg.authCapability is AuthCapability.Authenticated<*>)
            jcaCiphertext.takeLast(((alg.authCapability as AuthCapability.Authenticated<*>).tagLength.bytes.toInt()).toInt())
                .toByteArray() else null


    @Suppress("UNCHECKED_CAST")
    return when {
        alg.requiresNonce() -> when {
            alg.isAuthenticated() -> {
                (alg as SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<*>, NonceTrait.Required, *>)
                alg.sealedBoxFrom(nonce!!, ciphertext, authTag!!)
            }

            else -> alg.sealedBoxFrom(nonce!!, ciphertext)
        }

        else -> when {
            alg.isAuthenticated() -> {
                (alg as SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<*>, NonceTrait.Without, *>)
                alg.sealedBoxFrom(ciphertext, authTag!!)
            }

            else -> alg.sealedBoxFrom(ciphertext)
        }

    }.getOrThrow() as SealedBox<A, I, out K>
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

@JvmName("doDecryptAuthenticated")
internal actual fun SealedBox<Authenticated.Integrated, *, out KeyType.Integrated>.doDecryptAEAD(
    secretKey: ByteArray,
    authenticatedData: ByteArray
): ByteArray {
    if (!this.hasNonce()) TODO("AEAD algorithm $algorithm is UNSUPPORTED")

    if ((algorithm !is SymmetricEncryptionAlgorithm.ChaCha20Poly1305) && (algorithm !is SymmetricEncryptionAlgorithm.AES.GCM))
        TODO("AEAD algorithm $algorithm is UNSUPPORTED")

    return aeadDecrypt(
        algorithm,
        secretKey,
        nonce,
        encryptedData,
        authTag,
        authenticatedData
    )

}

internal actual fun SealedBox<AuthCapability.Unauthenticated, *, out KeyType.Integrated>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    if (algorithm !is SymmetricEncryptionAlgorithm.AES<*, *, *>)
        TODO("unauthenticated algorithm $algorithm is UNSUPPORTED")

    @OptIn(HazardousMaterials::class)
    if ((algorithm is SymmetricEncryptionAlgorithm.AES.ECB) || (algorithm is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394)) {
        return Cipher.getInstance(algorithm.jcaName).also { cipher ->
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(secretKey, algorithm.jcaKeySpec),
            )
        }.doFinal(encryptedData)
    }

    this as SealedBox.WithNonce
    return Cipher.getInstance(algorithm.jcaName).also { cipher ->
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(secretKey, algorithm.jcaKeySpec),
            IvParameterSpec(this@doDecrypt.nonce)
        )
    }.doFinal(encryptedData)
}

internal fun aeadDecrypt(
    algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<KeyType.Integrated>, NonceTrait.Required, KeyType.Integrated>,
    secretKey: ByteArray,
    nonce: ByteArray,
    encryptedData: ByteArray,
    authTag: ByteArray,
    aad: ByteArray?
): ByteArray = Cipher.getInstance(algorithm.jcaName).also { cipher ->
    cipher.init(
        Cipher.DECRYPT_MODE,
        SecretKeySpec(secretKey, algorithm.jcaKeySpec),
        if (algorithm is SymmetricEncryptionAlgorithm.AES.GCM)
            GCMParameterSpec(authTag.size * 8, nonce)
        else IvParameterSpec(nonce)
    )
    aad?.let { cipher.updateAAD(it) }
}.doFinal(encryptedData + authTag)

