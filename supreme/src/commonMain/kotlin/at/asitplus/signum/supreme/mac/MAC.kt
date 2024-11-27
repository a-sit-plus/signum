package at.asitplus.signum.supreme.mac

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MAC
import at.asitplus.signum.indispensable.misc.xor
import at.asitplus.signum.supreme.hash.digest


fun MAC.mac(key: ByteArray, msg: ByteArray) = mac(key, sequenceOf(msg))
fun MAC.mac(key: ByteArray, msg: Iterable<ByteArray>) = mac(key, msg.asSequence())

private val HMAC.B get() = digest.inputBlockSize.bytes.toInt()
private val HMAC.innerPad get() = ByteArray(B) { 0x36 }
private val HMAC.outerPad get() = ByteArray(B) { 0x5C }

fun MAC.mac(key: ByteArray, msg: Sequence<ByteArray>): KmmResult<ByteArray> = catching {
    when (this@mac) {
        is HMAC -> hmac(key, msg)
        else -> TODO()
    }
}

internal fun HMAC.hmac(key: ByteArray, msg: Sequence<ByteArray>): ByteArray {
    val realKey = (if (key.size <= B) key else digest.digest(key)).let {
        if (it.size < B) it + ByteArray(B - it.size) else it
    }
    check(realKey.size == B)
    val innerHash = digest.digest(sequenceOf(realKey xor innerPad) + msg)
    val outerHash = digest.digest(sequenceOf(realKey xor outerPad, innerHash))
    return outerHash
}


