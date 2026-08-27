package at.asitplus.signum.supreme.mac

import at.asitplus.signum.indispensable.digest.digest
import at.asitplus.signum.indispensable.integrity.HMAC
import at.asitplus.signum.indispensable.integrity.MessageAuthenticationCode
import at.asitplus.signum.indispensable.integrity.MessageAuthenticationCodeOperationsProvider
import at.asitplus.signum.indispensable.integrity.SpecializedMessageAuthenticationCode
import at.asitplus.signum.indispensable.integrity.mac
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.internals.xor
import kotlin.experimental.and
import kotlin.experimental.inv

private val HMAC.blockLength get() = digest.inputBlockSize.bytes.toInt()
private val HMAC.innerPad get() = ByteArray(blockLength) { 0x36 }
private val HMAC.outerPad get() = ByteArray(blockLength) { 0x5C }

private fun ByteArray.truncateTo(size: BitLength): ByteArray {
    val a = if (size.bytes.toInt() < this.size) this.copyOf(size.bytes.toInt()) else this
    require(a.size == size.bytes.toInt())
    if (size.bitSpacing != 0u)
        a[a.lastIndex] = a[a.lastIndex] and ((1 shl size.bitSpacing.toInt())-1).toByte().inv();
    return a
}

object SupremeHMACOperationsProvider : MessageAuthenticationCodeOperationsProvider {
    override suspend fun doMAC(mac: MessageAuthenticationCode, key: ByteArray, message: Sequence<ByteArray>) =
        when(mac) {
            is HMAC -> mac.hmac(key, message)
            is MessageAuthenticationCode.Truncated ->
                mac.inner.mac(key, message).truncateTo(mac.outputLength)
        }
}

internal suspend fun HMAC.hmac(key: ByteArray, msg: Sequence<ByteArray>): ByteArray {
    val realKey = (if (key.size <= blockLength) key else digest.digest(key)).let {
        if (it.size < blockLength) it + ByteArray(blockLength - it.size) else it
    }
    check(realKey.size == blockLength)
    val innerHash = digest.digest(sequenceOf(realKey xor innerPad) + msg)
    val outerHash = digest.digest(sequenceOf(realKey xor outerPad, innerHash))
    return outerHash
}


