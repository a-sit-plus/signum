package at.asitplus.signum.supreme.crypt

import at.asitplus.signum.indispensable.EncryptionAlgorithm
import at.asitplus.signum.supreme.aes.AESwift
import at.asitplus.signum.supreme.toByteArray
import at.asitplus.signum.supreme.toNSData
import kotlinx.cinterop.ExperimentalForeignApi
actual internal fun initCipher(
    cipher: EncryptionAlgorithm,
    key: ByteArray,
    iv: ByteArray?,
    aad: ByteArray?
): PlatformCipher {
   if(cipher !is EncryptionAlgorithm.AES.GCM) throw IllegalArgumentException()
    return AESContainer(key, iv!!, aad!!)
}

private data class AESContainer(val key: ByteArray, val iv: ByteArray, val aad: ByteArray)

@OptIn(ExperimentalForeignApi::class)
actual internal fun PlatformCipher.encrypt(data: ByteArray): ByteArray {
    this as AESContainer
  return  AESwift.cryptoDemoCombinedDataWithPlain(data.toNSData(), key.toNSData(), iv.toNSData(), aad.toNSData())!!.toByteArray()
}

