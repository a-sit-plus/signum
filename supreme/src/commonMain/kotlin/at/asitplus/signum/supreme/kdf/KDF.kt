package at.asitplus.signum.supreme.kdf

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.kdf.HKDF
import at.asitplus.signum.indispensable.kdf.KDF
import at.asitplus.signum.supreme.mac.mac
import kotlin.math.min

fun KDF.expand(pseudoRandomKey: ByteArray, info: ByteArray, length: Int): KmmResult<ByteArray> = catching {
    when (this) {
        is HKDF -> {
            val output = ByteArray(length)
            var T = byteArrayOf()
            var populated = 0
            var nextI = 1
            while (populated < length) {
                check(nextI <= 255)
                T = hmac.mac(pseudoRandomKey, sequenceOf(T, info, byteArrayOf((nextI++).toUByte().toByte())))
                    .getOrThrow()
                val toCopy = min(length - populated, T.size)
                T.copyInto(output, populated, 0, toCopy)
                populated += toCopy
            }
            output
        }
    }
}

fun KDF.extract(salt: ByteArray?, InputKeyMaterial: ByteArray): KmmResult<ByteArray> = when (this) {
    is HKDF -> hmac.mac(salt ?: ByteArray(outputLength), InputKeyMaterial)
}
