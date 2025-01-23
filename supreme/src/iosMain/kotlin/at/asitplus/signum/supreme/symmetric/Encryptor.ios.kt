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
    iv: ByteArray?,
    aad: ByteArray?
): CipherParam<T, A> {
    if (algorithm.iv !is IV.Required) TODO()
    algorithm as SymmetricEncryptionAlgorithm<*, IV.Required>
    val nonce = iv ?: algorithm.randomIV()
    return CipherParam<ByteArray, A>(algorithm, key, nonce, aad) as CipherParam<T, A>
}

@OptIn(ExperimentalForeignApi::class)
internal actual fun <A : CipherKind, I : IV> CipherParam<*, A>.doEncrypt(data: ByteArray): SealedBox<A, I, SymmetricEncryptionAlgorithm<A, I>> {
    this as CipherParam<ByteArray, A>
    if (alg.iv !is IV.Required) TODO()

    require(iv != null)
    val nsIV = iv.toNSData()
    val nsAAD = aad?.toNSData()

    if (alg !is SymmetricEncryptionAlgorithm.AES<*>)
        TODO()


    return when (alg) {
        is AES.CBC.Plain -> {
            val padded = (alg as AES<*>).addPKCS7Padding(data)
            val bytes: ByteArray = swiftcall {
                CBC.crypt(kCCEncrypt.toLong(), padded.toNSData(), platformData.toNSData(), nsIV, error)
            }.toByteArray()
            alg.sealedBox(iv, bytes)
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
    if (ciphertext.algorithm.iv !is IV.Required) TODO()
    ciphertext as Ciphertext.Authenticated
    this as SealedBox.WithIV
    require(ciphertext.algorithm is AES<*>) { "Only AES is supported" }
    return swiftcall {
        GCM.decrypt(
            ciphertext.encryptedData.toNSData(),
            secretKey.toNSData(),
            iv.toNSData(),
            (ciphertext as Ciphertext.Authenticated).authTag.toNSData(),
            (ciphertext as Ciphertext.Authenticated).authenticatedData?.toNSData(),
            error
        )
    }.toByteArray()
}

@OptIn(ExperimentalForeignApi::class)
actual internal fun SealedBox<CipherKind.Unauthenticated, *, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>>.doDecrypt(
    secretKey: ByteArray
): ByteArray {
    if (ciphertext.algorithm.iv !is IV.Required) TODO()
    this as SealedBox.WithIV
    require(ciphertext.algorithm is AES<*>) { "Only AES is supported" }
    val decrypted = swiftcall {
        CBC.crypt(
            kCCDecrypt.toLong(),
            this@doDecrypt.ciphertext.encryptedData.toNSData(),
            secretKey.toNSData(),
            this@doDecrypt.iv!!.toNSData(),
            error
        )
    }.toByteArray()
    return (ciphertext.algorithm as AES<*>).removePKCS7Padding(decrypted)
}
