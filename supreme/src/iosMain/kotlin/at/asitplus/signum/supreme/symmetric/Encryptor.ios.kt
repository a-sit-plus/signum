package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES
import at.asitplus.signum.internals.swiftcall
import at.asitplus.signum.internals.toByteArray
import at.asitplus.signum.internals.toNSData
import at.asitplus.signum.supreme.aes.CBC
import at.asitplus.signum.supreme.aes.GCM
import kotlinx.cinterop.ExperimentalForeignApi
import platform.CoreCrypto.kCCDecrypt
import platform.CoreCrypto.kCCEncrypt


internal actual fun <T, A : CipherKind, E : SymmetricEncryptionAlgorithm<A, *>> initCipher(
    algorithm: E,
    key: ByteArray,
    nonce: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A> {
    if (algorithm.nonce !is Nonce.Required) TODO()
    algorithm as SymmetricEncryptionAlgorithm<*, Nonce.Required>
    val nonce = nonce ?: algorithm.randomNonce()
    return CipherParam<ByteArray, A>(algorithm, key, nonce, aad) as CipherParam<T, A>
}

@OptIn(ExperimentalForeignApi::class)
internal actual fun <A : CipherKind, I : Nonce> CipherParam<*, A>.doEncrypt(data: ByteArray): SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>> {
    this as CipherParam<ByteArray, A>
    if (alg.nonce !is Nonce.Required) TODO()

    require(nonce != null)
    val nsIV = nonce.toNSData()
    val nsAAD = aad?.toNSData()

    if (alg !is SymmetricEncryptionAlgorithm.AES<*>)
        TODO()


    return when (alg) {
        is AES.CBC.Unauthenticated -> {
            val padded = (alg as AES<*>).addPKCS7Padding(data)
            val bytes: ByteArray = swiftcall {
                CBC.crypt(kCCEncrypt.toLong(), padded.toNSData(), platformData.toNSData(), nsIV, error)
            }.toByteArray()
            alg.sealedBox(nonce, bytes)
        }
        is AES.GCM -> {
            val ciphertext = GCM.encrypt(data.toNSData(), platformData.toNSData(), nsIV, nsAAD)
            if (ciphertext == null) throw UnsupportedOperationException("Error from swift code!")
            alg.sealedBox(ciphertext.iv().toByteArray(),
                ciphertext.ciphertext().toByteArray(),
                ciphertext.authTag().toByteArray(),
                aad
            )
        }
        else -> TODO()
    } as SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>>
}

private fun BlockCipher<*, *>.addPKCS7Padding(plain: ByteArray): ByteArray {
    val blockBytes = blockSize.bytes.toInt()
    val diff = blockBytes - (plain.size % blockBytes)
    return if (diff == 0)
        plain + ByteArray(blockBytes) { blockBytes.toByte() }
    else plain + ByteArray(diff) { diff.toByte() }
}


private fun BlockCipher<*, *>.removePKCS7Padding(plainWithPadding: ByteArray): ByteArray {
    val paddingBytes = plainWithPadding.last().toInt()
    require(paddingBytes > 0) { "Illegal padding: $paddingBytes" }
    require(plainWithPadding.takeLast(paddingBytes).all { it.toInt() == paddingBytes }) { "Padding not consistent" }
    require(plainWithPadding.size - paddingBytes >= 0) { "Too much padding: data ${plainWithPadding.joinToString()}" }
    return plainWithPadding.sliceArray(0..<plainWithPadding.size - paddingBytes)
}


@OptIn(ExperimentalForeignApi::class)
actual internal fun SealedBox<CipherKind.Authenticated.Integrated, *, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.Integrated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    if (algorithm.nonce !is Nonce.Required) TODO()
    this as SealedBox.WithNonce
    require(algorithm is AES<*>) { "Only AES is supported" }
    return swiftcall {
        GCM.decrypt(
            encryptedData.toNSData(),
            secretKey.toNSData(),
            this@doDecrypt.nonce.toNSData(),
            authTag.toNSData(),
            authenticatedData?.toNSData(),
            error
        )
    }.toByteArray()
}

@OptIn(ExperimentalForeignApi::class)
actual internal fun SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    if (algorithm.nonce !is Nonce.Required) TODO()
    this as SealedBox.WithNonce
    require(algorithm is AES<*>) { "Only AES is supported" }
    val decrypted = swiftcall {
        CBC.crypt(
            kCCDecrypt.toLong(),
            this@doDecrypt.encryptedData.toNSData(),
            secretKey.toNSData(),
            this@doDecrypt.nonce!!.toNSData(),
            error
        )
    }.toByteArray()
    return (algorithm as AES<*>).removePKCS7Padding(decrypted)
}
