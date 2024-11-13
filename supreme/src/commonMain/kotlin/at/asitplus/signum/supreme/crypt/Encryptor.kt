package at.asitplus.signum.supreme.crypt

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.EncryptionAlgorithm

abstract class Encryptor internal constructor(
    protected val cipher: EncryptionAlgorithm,
    protected val key: ByteArray,
    protected val iv: ByteArray?,
    protected val aad: ByteArray?
) {

    protected val platformCipher: PlatformCipher = initCipher(cipher, key, iv, aad)


    fun encrypt(data: ByteArray): KmmResult<ByteArray> {
        return catching { platformCipher.encrypt(data) }
    }

}

internal typealias PlatformCipher = Any

expect internal fun initCipher(cipher: EncryptionAlgorithm, key: ByteArray, iv: ByteArray?, aad: ByteArray?): PlatformCipher
expect internal fun PlatformCipher.encrypt(data: ByteArray): ByteArray