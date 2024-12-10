package at.asitplus.signum.supreme.kdf

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.encoding.toUnsignedByteArray
import at.asitplus.signum.indispensable.kdf.HKDF
import at.asitplus.signum.indispensable.kdf.PBKDF2
import at.asitplus.signum.internals.padStart
import at.asitplus.signum.internals.xor
import at.asitplus.signum.supreme.mac.mac
import kotlin.math.min

fun HKDF.expand(pseudoRandomKey: ByteArray, info: ByteArray, length: Int): KmmResult<ByteArray> = catching {
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

fun HKDF.extract(salt: ByteArray?, InputKeyMaterial: ByteArray): KmmResult<ByteArray> =
    hmac.mac(salt ?: ByteArray(outputLength), InputKeyMaterial)


private fun PBKDF2.int(v: UInt) =
    v.toLong().toUnsignedByteArray().padStart(4, 0x00)

operator fun PBKDF2.invoke(password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int): KmmResult<ByteArray> =
    catching {
        require(iterations > 0) { "iterations must be greater than 0" }
        val result = ByteArray(dkLen)
        var populated = 0
        var i = 0u
        while (populated < dkLen) {
            // the loop body is the RFC's "F"
            require(i < UInt.MAX_VALUE) { "derived key too long" }
            ++i
            var U = prf.mac(password, sequenceOf(salt, int(i))).getOrThrow()
            var T = U
            repeat(iterations - 1) {
                U = prf.mac(password, U).getOrThrow()
                T = T xor U
            }
            val toCopy = min(T.size, dkLen - populated)
            T.copyInto(result, populated, 0, toCopy)
            populated += toCopy
        }
        result
    }
