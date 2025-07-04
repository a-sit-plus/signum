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
import at.asitplus.signum.internals.subview
import at.asitplus.signum.internals.toLEByteArray
import at.asitplus.signum.internals.toUIntArrayLE
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
            val B = PBKDF2.HMAC_SHA256(1).derive(ikm, salt, parallelization * 128 * blockSize)
            with(SCryptMixer(this)) {
                repeat(parallelization) { i -> scryptROMix(ByteArrayView(B, i * 128 * blockSize, 128 * blockSize)) }
            }
            PBKDF2.HMAC_SHA256(1).derive(ikm, B, derivedKeyLength.bytes.toInt())
        }
        is HKDF.WithInfo -> derive(salt, ikm, derivedKeyLength)
    }
}

private suspend fun HKDF.WithInfo.derive(salt: ByteArray, ikm: ByteArray, derivedKeyLength: BitLength): ByteArray =
    hkdf.extract(salt, ikm).getOrThrow().let { hkdf.expandStep(it, info, derivedKeyLength).getOrThrow() }

/**
 * HKDF `expand` step. **NOT A FULL KDF!**
 * @param pseudoRandomKey the input key material, which should already be pseudo-random.
 * @param info context
 * @param derivedKeyLength derived key length
 */
suspend fun HKDF.expandStep(pseudoRandomKey: ByteArray, info: ByteArray, derivedKeyLength: BitLength): KmmResult<ByteArray> = catching {
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
 * HDKF `extract` step generating a pseudo-random key from `salt` and `ikm`. **NOT A FULL KDF!**
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

fun SCrypt.integerify(B: ByteArrayView): Int =
    ((B[B.size - 64].toUByte().toULong() shl 0) or
            (B[B.size - 63].toUByte().toULong() shl 8) or
            (B[B.size - 62].toUByte().toULong() shl 16) or
            (B[B.size - 61].toUByte().toULong() shl 24) or
            (B[B.size - 60].toUByte().toULong() shl 32) or
            (B[B.size - 59].toUByte().toULong() shl 40) or
            (B[B.size - 58].toUByte().toULong() shl 48) or
            (B[B.size - 57].toUByte().toULong() shl 56)).and(/*"n - 1"*/(cost - 1).toULong()).toInt()


@OptIn(ExperimentalUnsignedTypes::class)
@Suppress("NOTHING_TO_INLINE")
private class SCryptMixer(private val sCrypt: SCrypt) {

    private inline fun R(a: UInt, b: Int) =
        ((a shl b) or (a shr (32 - b)))

    private val salsaInput = UIntArray(16)
    private val salsaScratch = UIntArray(16)
    private inline fun salsa(i1: Int, i2: Int, i3: Int, i4: Int) {
        salsaScratch[i1] = salsaScratch[i1] xor R(salsaScratch[i2] + salsaScratch[i3], 7)
        salsaScratch[i4] = salsaScratch[i4] xor R(salsaScratch[i1] + salsaScratch[i2], 9)
        salsaScratch[i3] = salsaScratch[i3] xor R(salsaScratch[i4] + salsaScratch[i1], 13)
        salsaScratch[i2] = salsaScratch[i2] xor R(salsaScratch[i3] + salsaScratch[i4], 18)
    }

    /** in-place salsa20/8 permutation */
    fun salsa20_8core(block: ByteArrayView) {
        check(block.size == 64)
        block.toUIntArrayLE(salsaInput)
        salsaInput.copyInto(salsaScratch)
        repeat(4) {
            salsa(4, 0, 12, 8)
            salsa(9, 5, 1, 13)
            salsa(14, 10, 6, 2)
            salsa(3, 15, 11, 7)
            salsa(1, 0, 3, 2)
            salsa(6, 5, 4, 7)
            salsa(11, 10, 9, 8)
            salsa(12, 15, 14, 13)
        }
        repeat(16) { salsaScratch[it] += salsaInput[it] }
        salsaScratch.toLEByteArray(block)
    }

    private val y = ByteArray(128 * sCrypt.blockSize)
    fun scryptBlockMix(blocks: ByteArrayView) {
        check(blocks.size == 128 * sCrypt.blockSize)
        var X = blocks.subview(128 * sCrypt.blockSize - 64, 64)
        repeat(2 * sCrypt.blockSize) { i ->
            val Yi = y.subview(64 * i, 64)
            Yi.replaceWith(X)
            Yi.xor_inplace(blocks.subview(64 * i, 64))
            salsa20_8core(Yi)
            X = Yi
        }
        repeat(2 * sCrypt.blockSize) { i ->
            blocks.subview(i * 64, 64).replaceWith(
                when {
                    i < sCrypt.blockSize -> y.subview((2 * i) * 64, 64)
                    else -> y.subview((2 * (i - sCrypt.blockSize) + 1) * 64, 64)
                }
            )
        }
    }

    private val v = ByteArray(128 * sCrypt.blockSize * sCrypt.cost)
    private val x = ByteArrayView(ByteArray(128 * sCrypt.blockSize))
    fun scryptROMix(bytes: ByteArrayView) {
        check(bytes.size == 128 * sCrypt.blockSize)
        x.replaceWith(bytes)
        repeat(sCrypt.cost) { i ->
            v.subview(i * 128 * sCrypt.blockSize, 128 * sCrypt.blockSize).replaceWith(x)
            scryptBlockMix(x)
        }
        repeat(sCrypt.cost) {
            val j = sCrypt.integerify(x)
            x.xor_inplace(v.subview(j * 128 * sCrypt.blockSize, 128 * sCrypt.blockSize))
            scryptBlockMix(x)
        }
        bytes.replaceWith(x)
    }
}