package at.asitplus.signum.supreme.ksf

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.kdf.PBKDF2
import at.asitplus.signum.indispensable.ksf.SCrypt
import at.asitplus.signum.internals.ByteArrayView
import at.asitplus.signum.supreme.kdf.invoke

fun SCrypt.stretch(msg: ByteArray) = invoke(msg, ByteArray(16), 32)

operator fun SCrypt.invoke(P: ByteArray, S: ByteArray, dkLen: Int): KmmResult<ByteArray> = catching {
    val B = PBKDF2.HMAC_SHA256(P, S, 1, parallelization * 128 * blockSize).getOrThrow()
    with(Mixer()) {
        repeat(parallelization) { i -> scryptROMix(ByteArrayView(B, i * 128 * blockSize, 128 * blockSize)) }
    }
    PBKDF2.HMAC_SHA256(P, B, 1, dkLen).getOrThrow()
}