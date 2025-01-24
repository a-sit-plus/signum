package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.symmetric.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

actual internal fun <T, A : CipherKind, E : SymmetricEncryptionAlgorithm<A, *>> initCipher(
    algorithm: E,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A> {
    if (algorithm.nonce is Nonce.Without) TODO()
    algorithm as SymmetricEncryptionAlgorithm<*, Nonce.Required>


    @OptIn(HazardousMaterials::class)
    val nonce = nonce ?: algorithm.randomNonce()

    return if (algorithm is SymmetricEncryptionAlgorithm.AES<*>)
        AESJVM.initCipher(algorithm, key, nonce, aad) as CipherParam<T, A>
    else if (algorithm is SymmetricEncryptionAlgorithm.ChaCha20Poly1305)
        ChaChaJVM.initCipher(key, nonce, aad) as CipherParam<T, A>
    else TODO()
}

actual internal fun <A : CipherKind, I : Nonce> CipherParam<*, A>.doEncrypt(data: ByteArray): SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>> {
    (this as CipherParam<Cipher, A>)
    val jcaCiphertext = platformData.doFinal(data)

    val ciphertext =
        if (alg.cipher is CipherKind.Authenticated) jcaCiphertext.dropLast(((alg.cipher as CipherKind.Authenticated).tagLen.bytes.toInt()).toInt())
            .toByteArray()
        else jcaCiphertext
    val authTag =
        if (alg.cipher is CipherKind.Authenticated) jcaCiphertext.takeLast(((alg.cipher as CipherKind.Authenticated).tagLen.bytes.toInt()).toInt())
            .toByteArray() else null

    return (if (alg.nonce is Nonce.Without) when (alg.cipher) {
        is CipherKind.Unauthenticated -> (alg as SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, Nonce.Without>).sealedBox(
            ciphertext
        )

        is CipherKind.Authenticated -> {
            (alg as SymmetricEncryptionAlgorithm<CipherKind.Authenticated, Nonce.Without>).sealedBox(
                ciphertext,
                authTag!!,
                aad
            )
        }

        else -> throw IllegalArgumentException("Unreachable code")
    } else when (alg.cipher) {
        is CipherKind.Unauthenticated -> (alg as SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, Nonce.Required>).sealedBox(
            nonce!!,
            ciphertext
        )

        is CipherKind.Authenticated -> {
            (alg as SymmetricEncryptionAlgorithm<CipherKind.Authenticated, Nonce.Required>).sealedBox(
                nonce!!,
                ciphertext,
                authTag!!,
                aad
            )
        }

        else -> throw IllegalArgumentException("Unreachable code")
    }) as SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>>
}

val SymmetricEncryptionAlgorithm<*, *>.jcaName: String
    get() = when (this) {
        is SymmetricEncryptionAlgorithm.AES.GCM -> "AES/GCM/NoPadding"
        is SymmetricEncryptionAlgorithm.AES.CBC<*> -> "AES/CBC/PKCS5Padding"
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> "ChaCha20-Poly1305"
        else -> TODO()
    }

val SymmetricEncryptionAlgorithm<*, *>.jcaKeySpec: String
    get() = when (this) {
        is SymmetricEncryptionAlgorithm.AES<*> -> "AES"
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> "ChaCha20"
        else -> TODO()
    }

@JvmName("doEncryptAuthenticated")
actual internal fun SealedBox<CipherKind.Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    this as SealedBox.WithNonce
    if (algorithm !is SymmetricEncryptionAlgorithm.AES.GCM) TODO()

    return AESJVM.gcmDecrypt(
        algorithm as SymmetricEncryptionAlgorithm.AES.GCM,
        secretKey,
        nonce,
        encryptedData,
        authTag,
        authenticatedData
    )
}


actual internal fun SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    if ((algorithm !is SymmetricEncryptionAlgorithm.AES<*>) && (algorithm !is SymmetricEncryptionAlgorithm.ChaCha20Poly1305))
        TODO()

    this as SealedBox.WithNonce
    return Cipher.getInstance(algorithm.jcaName).also { cipher ->
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(secretKey, algorithm.jcaKeySpec),
            IvParameterSpec(this@doDecrypt.nonce)
        )
    }.doFinal(encryptedData)
}

