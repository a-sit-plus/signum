package at.asitplus.signum.supreme.mac

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.misc.xor
import at.asitplus.signum.supreme.hash.digest


interface MAC {
    fun mac(key: ByteArray, msg: Sequence<ByteArray>): ByteArray
    /** output size of MAC */
    val Nm: Int
}
fun MAC.mac(key: ByteArray, msg: ByteArray) = mac(key, sequenceOf(msg))
fun MAC.mac(key: ByteArray, msg: Iterable<ByteArray>) = mac(key, msg.asSequence())

/**
 * RFC 2104 HMAC
 */
enum class HMAC(val digest: Digest) : MAC {
    SHA1(Digest.SHA1),
    SHA256(Digest.SHA256),
    SHA384(Digest.SHA384),
    SHA512(Digest.SHA512);

    companion object {
        operator fun invoke(digest: Digest) = when (digest) {
            Digest.SHA1 -> SHA1
            Digest.SHA256 -> SHA256
            Digest.SHA384 -> SHA384
            Digest.SHA512 -> SHA512
        }
    }

    private val B = digest.inputBlockSize.bytes.toInt()
    private val innerPad = ByteArray(B) { 0x36 }
    private val outerPad = ByteArray(B) { 0x5C }
    override fun mac(key: ByteArray, msg: Sequence<ByteArray>): ByteArray {
        val realKey = (if (key.size <= B) key else digest.digest(key)).let {
            if (it.size < B) it + ByteArray(B-it.size) else it
        }
        check(realKey.size == B)
        val innerHash = digest.digest(sequenceOf(realKey xor innerPad) + msg)
        val outerHash = digest.digest(sequenceOf(realKey xor outerPad, innerHash))
        return outerHash
    }
    override val Nm: Int get() = digest.outputLength.bytes.toInt()
}
