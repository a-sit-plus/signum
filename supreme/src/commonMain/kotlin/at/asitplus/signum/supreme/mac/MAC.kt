package at.asitplus.signum.supreme.mac

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.HMAC
import at.asitplus.signum.indispensable.MessageAuthenticationCode
import at.asitplus.signum.indispensable.SpecializedMessageAuthenticationCode
import at.asitplus.signum.internals.xor
import at.asitplus.signum.supreme.hash.digest


fun MessageAuthenticationCode.mac(key: ByteArray, msg: ByteArray) = mac(key, sequenceOf(msg))
fun MessageAuthenticationCode.mac(key: ByteArray, msg: Iterable<ByteArray>) = mac(key, msg.asSequence())

private val HMAC.blockLength get() = digest.inputBlockSize.bytes.toInt()
private val HMAC.innerPad get() = ByteArray(blockLength) { 0x36 }
private val HMAC.outerPad get() = ByteArray(blockLength) { 0x5C }

fun SpecializedMessageAuthenticationCode.mac(key: ByteArray, msg: Sequence<ByteArray>): KmmResult<ByteArray> =
    algorithm.mac(key, msg)

fun MessageAuthenticationCode.mac(key: ByteArray, msg: Sequence<ByteArray>): KmmResult<ByteArray> = catching {
    when (this@mac) {
        is HMAC -> hmac(key, msg)
    }
}

internal fun HMAC.hmac(key: ByteArray, msg: Sequence<ByteArray>): ByteArray {
    val realKey = (if (key.size <= blockLength) key else digest.digest(key)).let {
        if (it.size < blockLength) it + ByteArray(blockLength - it.size) else it
    }
    check(realKey.size == blockLength)
    val innerHash = digest.digest(sequenceOf(realKey xor innerPad) + msg)
    val outerHash = digest.digest(sequenceOf(realKey xor outerPad, innerHash))
    return outerHash
}


