package at.asitplus.signum.supreme.crypt

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.EncryptionAlgorithm

class Encryptor internal constructor(
    protected val algorithm: EncryptionAlgorithm,
    protected val key: ByteArray,
    protected val iv: ByteArray?,
    protected val aad: ByteArray?
) {

    init {
        if (algorithm is EncryptionAlgorithm.WithIV) iv?.let {
            require((it.size * 8).toUInt() == algorithm.ivNumBits) { "IV must be exactly ${algorithm.ivNumBits} bits long" }
        }
        require((key.size * 8).toUInt() == algorithm.keyNumBits) { "Key must be exactly ${algorithm.keyNumBits} bits long" }
    }


    protected val platformCipher: PlatformCipher = initCipher(algorithm, key, iv, aad)


    fun encrypt(data: ByteArray): KmmResult<Ciphertext> {
        return  platformCipher.encrypt(data)
    }

}

internal typealias PlatformCipher = Any

expect internal fun initCipher(
    algorithm: EncryptionAlgorithm,
    key: ByteArray,
    iv: ByteArray?,
    aad: ByteArray?
): PlatformCipher

expect internal fun PlatformCipher.encrypt(data: ByteArray): KmmResult<Ciphertext>