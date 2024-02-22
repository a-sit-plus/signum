// Based on UVarInt.kt (https://github.com/walt-id/multiformat-kotlin-multiplatform/blob/main/src/commonMain/kotlin/org/erwinkok/multiformat/util/UVarInt.kt)
// Originally Copyright (c) 2022 Erwin Kok under the term of the BSD-3-Clause license.

package at.asitplus.crypto.datatypes.misc


/**
 * TODO better description
 * `bytes` holds encoded value
 */
class UVarInt(val bytes: ByteArray) {
    init {
        //TODO("Check that value is indeed valid encoding")
    }
//    constructor(src: ByteArray) : this(
//        src.fold(0uL) { acc, byte -> (acc shl 8) + (byte.toULong()) }.toULong()
//    )

    //fun toByteArray() = value.toLong().encodeToByteArray()


    private val ErrOverflow = Error("varints larger than uint63 not supported")
    private val ErrNotMinimal = Error("varint not minimally encoded")

    // MaxLenUvarint63 is the maximum number of bytes representing an uvarint in
    // this encoding, supporting a maximum value of 2^63 (uint63), aka
    // MaxValueUvarint63.
    private val MaxLenUvarint63 = 9L


    /**
     * decodes a UVarInt encoded bytearray back to the original number
     */
    fun decode(): ULong {
        var value = 0uL
        var s = 0
        var i = 0
        while (true) {
            val uByte = bytes[i].toUByte()
            if ((i == 8 && uByte >= 0x80u) || i >= MaxLenUvarint63) {
                // this is the 9th and last byte we're willing to read, but it
                // signals there's more (1 in MSB).
                // or this is the >= 10th byte, and for some reason we're still here.
                throw Error(ErrOverflow)
            }
            if (uByte < 0x80u) {
                if (uByte == 0u.toUByte() && s > 0) {
                    throw Error(ErrNotMinimal)
                }
                return value or (uByte.toULong() shl s)
            }
            value = value or ((uByte and 0x7fu).toULong() shl s)
            s += 7
            i++
        }
    }

    companion object {

        /**
         * takes normal (!) ULong and transforms it to UVarInt (i.e. UVarInt encoded Bytearray)
         */
        fun encode(x: ULong): UVarInt {
            var tmp = x
            var i = 0
            val res = mutableListOf<Byte>()
            while (tmp >= 0x80u) {
                res += (((tmp and 0x7Fu) or 0x80u).toByte())
                tmp = (tmp.toLong() ushr 7).toULong()
                i++
            }
            res += (tmp and 0x7Fu).toByte()
            return UVarInt(res.toByteArray())
        }
    }
}

