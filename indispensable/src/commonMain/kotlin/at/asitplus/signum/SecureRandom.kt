package at.asitplus.signum

import org.kotlincrypto.random.CryptoRand
import kotlin.random.Random

/**
 * Wrapper over [org.kotlincrypto.random.CryptoRand.Default] to align with Kotlin's [kotlin.random.Random] interface
 */
object SecureRandom : Random() {
    override fun nextBits(bitCount: Int): Int {
        require(bitCount in 0..32)
        if (bitCount == 0) return 0

        val byteCount = (bitCount + 7) / 8
        val remBits = bitCount % 8 // bits used in the most significant byte (0 means full 8)
        val bytes = ByteArray(byteCount)
        CryptoRand.Default.nextBytes(bytes)

        // Zero out unused high bits in the most significant byte
        if (remBits != 0) {
            val mask = (1 shl remBits) - 1
            bytes[0] = (bytes[0].toInt() and mask).toByte()
        }

        // Assemble big-endian into Int
        var result = 0
        for (b in bytes) {
            result = (result shl 8) or (b.toInt() and 0xFF)
        }
        return result
    }

    override fun nextBytes(array: ByteArray): ByteArray = CryptoRand.Default.nextBytes(array)
}