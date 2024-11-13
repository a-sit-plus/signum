package at.asitplus.signum.supreme.crypt

import at.asitplus.signum.indispensable.EncryptionAlgorithm
import platform.CoreCrypto.CCCrypt
import platform.CoreCrypto.kCCAlgorithmAES
import platform.CoreCrypto.kCCEncrypt

actual internal fun initCipher(
    cipher: EncryptionAlgorithm,
    key: ByteArray,
    iv: ByteArray?,
    aad: ByteArray?
): PlatformCipher {
    return byteArrayOf()
}

actual internal fun PlatformCipher.encrypt(data: ByteArray): ByteArray = byteArrayOf()

