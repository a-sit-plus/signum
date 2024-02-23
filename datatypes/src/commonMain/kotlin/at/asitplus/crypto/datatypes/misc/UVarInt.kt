// Based on UVarInt.kt (https://github.com/walt-id/multiformat-kotlin-multiplatform/blob/main/src/commonMain/kotlin/org/erwinkok/multiformat/util/UVarInt.kt)
// Originally Copyright (c) 2022 Erwin Kok under the term of the BSD-3-Clause license.

package at.asitplus.crypto.datatypes.misc


/**
 * Unsigned varint datatype
 */
class UVarInt private constructor(private val number: ULong) {

    constructor(number: UInt) : this(number.toULong())

    /**
     * returns the ULong value of this UVarInt
     */
    fun toULong(): ULong = number

    /**
     * encodes this number's value into a ByteArray using varint encoding
     */
    fun encodeToByteArray(): ByteArray {
        var acc = number
        var i = 0
        val res = mutableListOf<Byte>()
        while (acc >= 0x80u) {
            res += (((acc and 0x7Fu) or 0x80u).toByte())
            acc = (acc.toLong() ushr 7).toULong()
            i++
        }
        return (res + (acc and 0x7Fu).toByte()).toByteArray()
    }

    companion object {
        // MaxLenUvarint63 is the maximum number of bytes representing an uvarint in
        // this encoding, supporting a maximum value of 2^63 (uint63), aka
        // MaxValueUvarint63.
        const val MaxLenUvarint63 = 9L

        /**
         * decodes a varint-encoded ByteArray into a UVarInt
         */
        @Throws(NumberFormatException::class)
        fun fromByteArray(bytes: ByteArray): UVarInt = UVarInt(decode(bytes))

        private fun decode(encoded: ByteArray): ULong {
            var value = 0uL
            var s = 0
            var i = 0
            while (true) {
                val uByte = encoded[i].toUByte()
                if ((i == 8 && uByte >= 0x80u) || i >= MaxLenUvarint63) {
                    // this is the 9th and last byte we're willing to read, but it
                    // signals there's more (1 in MSB).
                    // or this is the >= 10th byte, and for some reason we're still here.
                    throw NumberFormatException("varints larger than uint63 not supported")
                }
                if (uByte < 0x80u) {
                    if (uByte == 0u.toUByte() && s > 0) {
                        throw NumberFormatException("varint not minimally encoded")
                    }
                    return value or (uByte.toULong() shl s)
                }
                value = value or ((uByte and 0x7fu).toULong() shl s)
                s += 7
                i++
            }
        }
    }
}

