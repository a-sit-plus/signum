package at.asitplus.signum.supreme.kdf

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.encoding.toUnsignedByteArray
import at.asitplus.signum.indispensable.kdf.HKDF
import at.asitplus.signum.indispensable.kdf.KDF
import at.asitplus.signum.indispensable.kdf.PBKDF2
import at.asitplus.signum.indispensable.kdf.SCrypt
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.internals.ByteArrayView
import at.asitplus.signum.internals.padStart
import at.asitplus.signum.internals.xor
import at.asitplus.signum.supreme.mac.mac
import kotlin.math.min

/**
 * Derives a key using the specified [KDF] implementation.
 *
 * @param salt the salt to use
 * @param ikm the input key material
 * @param derivedKeyLength the length of the derived key
 *
 * Any other parameters are set during instantiation of the [KDF] implementation.
 */
suspend fun KDF.deriveKey(salt: ByteArray, ikm: ByteArray, derivedKeyLength: BitLength): KmmResult<ByteArray> = catching {
    when (this) {
        is PBKDF2.WithIterations -> derive(ikm, salt, derivedKeyLength.bytes.toInt())
        is SCrypt -> {
            val B = PBKDF2.HMAC_SHA256.WithIterations(1).derive(ikm, salt, parallelization * 128 * blockSize)
            with(Mixer()) {
                repeat(parallelization) { i -> scryptROMix(ByteArrayView(B, i * 128 * blockSize, 128 * blockSize)) }
            }
            PBKDF2.HMAC_SHA256.WithIterations(1).derive(ikm, B, derivedKeyLength.bytes.toInt())
        }
        is HKDF.WithInfo -> derive(salt, ikm, derivedKeyLength)
    }
}

private suspend fun HKDF.WithInfo.derive(salt: ByteArray, ikm: ByteArray, derivedKeyLength: BitLength): ByteArray =
    hkdf.extract(salt, ikm).getOrThrow().let { hkdf.expand(it, info, derivedKeyLength).getOrThrow() }

/**
 * HKDF `expand` step
 * @param pseudoRandomKey the input key material, which should already be pseudo-random.
 * @param info context
 * @param derivedKeyLength derived key length
 */
suspend fun HKDF.expand(pseudoRandomKey: ByteArray, info: ByteArray, derivedKeyLength: BitLength): KmmResult<ByteArray> = catching {
    val output = ByteArray(derivedKeyLength.bytes.toInt())
    var T = byteArrayOf()
    var populated = 0
    var nextI = 1
    while (populated < output.size) {
        check(nextI <= 255)
        T = hmac.mac(pseudoRandomKey, sequenceOf(T, info, byteArrayOf((nextI++).toUByte().toByte())))
            .getOrThrow()
        val toCopy = min(output.size - populated, T.size)
        T.copyInto(output, populated, 0, toCopy)
        populated += toCopy
    }
    output
}

/**
 * HDKF `extract` step generating a pseudo-random key from `salt` and `ikm`
 * @param salt optional salt. If not provided, defaults to `ByteArray(outputLength)`, i.e. ["a string of HashLen zeros"](https://datatracker.ietf.org/doc/html/rfc5869#section-2.2)
 * @param inputKeyMaterial input key material
 */
suspend fun HKDF.extract(salt: ByteArray?, inputKeyMaterial: ByteArray): KmmResult<ByteArray> =
    hmac.mac(salt ?: ByteArray(outputLength), inputKeyMaterial)


private fun PBKDF2.int(v: UInt) =
    v.toLong().toUnsignedByteArray().padStart(4, 0x00)

private suspend fun PBKDF2.WithIterations.derive(password: ByteArray, salt: ByteArray, dkLen: Int): ByteArray {
    require(iterations > 0) { "iterations must be greater than 0" }
    val result = ByteArray(dkLen)
    var populated = 0
    var i = 0u
    while (populated < dkLen) {
        // the loop body is RFC8018#Section-5.2's "F"
        require(i < UInt.MAX_VALUE) { "derived key too long" }
        ++i
        var U = pbkdf2.prf.mac(password, sequenceOf(salt, pbkdf2.int(i))).getOrThrow()
        var T = U
        repeat(iterations - 1) {
            U = pbkdf2.prf.mac(password, U).getOrThrow()
            T = T xor U
        }
        val toCopy = min(T.size, dkLen - populated)
        T.copyInto(result, populated, 0, toCopy)
        populated += toCopy
    }
    return result
}
