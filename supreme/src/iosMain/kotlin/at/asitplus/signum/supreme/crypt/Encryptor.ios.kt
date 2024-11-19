package at.asitplus.signum.supreme.crypt

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.EncryptionAlgorithm
import at.asitplus.signum.supreme.aes.AESwift
import at.asitplus.signum.supreme.swiftcall
import at.asitplus.signum.supreme.toByteArray
import at.asitplus.signum.supreme.toNSData
import kotlinx.cinterop.ExperimentalForeignApi

actual internal fun initCipher(
    algorithm: EncryptionAlgorithm,
    key: ByteArray,
    iv: ByteArray?,
    aad: ByteArray?
): PlatformCipher {
    if (algorithm !is EncryptionAlgorithm.AES.GCM) throw IllegalArgumentException()
    return AESContainer(key, iv!!, aad)
}

private data class AESContainer(val key: ByteArray, val iv: ByteArray, val aad: ByteArray?)

@OptIn(ExperimentalForeignApi::class)
actual internal fun PlatformCipher.encrypt(data: ByteArray): KmmResult<Ciphertext> {
    this as AESContainer
    val nsData = data.toNSData()
    val nsKey = key.toNSData()
    val nsIV = iv.toNSData()
    val nsAAD = aad?.toNSData()

    val ciphertext = AESwift.gcmWithPlain(nsData, nsKey, nsIV, nsAAD)
    if (ciphertext == null) return KmmResult.failure(UnsupportedOperationException("Error from swift code!"))


    return if (ciphertext.authTag() != null)
        KmmResult.success(
            Ciphertext.Authenticated(
                ciphertext.ciphertext().toByteArray(),
                ciphertext.iv().toByteArray(),
                ciphertext.authTag()!!.toByteArray(),
                aad
            )
        )
    else KmmResult.success(Ciphertext(ciphertext.ciphertext().toByteArray(), ciphertext.iv().toByteArray()))
}


@OptIn(ExperimentalForeignApi::class)
internal fun decrypt(ciphertext: Ciphertext, key: ByteArray): ByteArray? {

    return  swiftcall {
        AESwift.gcmDecryptWithCiphertext(
            ciphertext.encryptedData.toNSData(),
            key.toNSData(),
            ciphertext.iv!!.toNSData(),
            (ciphertext as Ciphertext.Authenticated).authTag.toNSData(),
            (ciphertext as Ciphertext.Authenticated).aad?.toNSData(),
            error
        )!!.toByteArray()
    }
}
