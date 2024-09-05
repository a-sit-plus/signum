package at.asitplus.signum.supreme.encrypt

import at.asitplus.KmmResult

interface SymmetricEncryption {
    fun encrypt(data: ByteArray): ByteArray
    fun decrypt(ciphertext: ByteArray): KmmResult<ByteArray>
}