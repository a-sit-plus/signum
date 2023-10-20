package at.asitplus.crypto.datatypes.asn1

import at.asitplus.crypto.datatypes.io.KmmBitSet

/**
 * ASN.1 BIT STRING
 */
class Asn1BitString private constructor(
    /**
     * Number fo bits needed to pad the bit string to a byte boundary
     */
    val numPaddingBits: Byte,

    /**
     * The raw bytes containing the bit string. The bits contained in [rawBytes] are laid out, as printed when calling
     * [KmmBitSet.toBitString], right-padded with [numPaddingBits] many zero bits to the last byte boundary.
     *
     * The overall [Asn1Primitive.content] resulting from [encodeToTlv] is `byteArrayOf(numPaddingBits, *rawBytes)`
     */
    val rawBytes: ByteArray,
) :
    Asn1Encodable<Asn1Primitive> {

    private constructor(derValue: Pair<Byte, ByteArray>) : this(derValue.first, derValue.second)

    /**
     * Creates an ASN.1 BIT STRING from the provided bitSet.
     * The transformation to [rawBytes] and the calculation of [numPaddingBits] happens
     * immediately in the constructor. Hence, modifications to the source KmmBitSet have no effect on the resulting [Asn1BitString].
     *
     * @param source the source [KmmBitSet], which is discarded after [rawBytes] and [numPaddingBits] have been calculated
     */
    constructor(source: KmmBitSet) : this(fromBitSet(source))

    /**
     * Transforms [rawBytes] and wraps into a [KmmBitSet]. The last [numPaddingBits] bits are ignored.
     * This is a deep copy and mirrors the bits in every byte to match
     * the native bitset layout where bit any byte indices run in opposite direction.
     * Hence, motifications to the resulting bitset do not affect [rawBytes]
     *
     * See [KmmBitSet] for more details on bit string representation vs memory layout.
     *
     */
    fun toBitSet(): KmmBitSet {
        val size = rawBytes.size.toLong() * 8 - numPaddingBits
        val bitset = KmmBitSet(size)
        for (i in rawBytes.indices) {
            val bitOffset = i.toLong() * 8L
            for (bitIndex in 0..<8) {
                val globalIndex = bitOffset + bitIndex
                if (globalIndex == size) return bitset
                bitset[globalIndex] = (rawBytes[i].toInt() and (0x80 shr bitIndex) != 0)
            }
        }
        return bitset
    }

    companion object : Asn1Decodable<Asn1Primitive, Asn1BitString> {
        private fun fromBitSet(bitSet: KmmBitSet): Pair<Byte, ByteArray> {
            val rawBytes = bitSet.bytes.map {
                var res = 0
                for (i in 0..7) {
                    if (it.toUByte().toInt() and (0x80 shr i) != 0) res = res or (0x01 shl i)//(0x80 shl (7 - i))
                }
                res.toUByte().toByte()
            }.toByteArray()
            return ((8 - (bitSet.length() % 8)) % 8).toByte() to rawBytes
        }

        override fun decodeFromTlv(src: Asn1Primitive): Asn1BitString {
            if (src.tag != BERTags.BIT_STRING) throw IllegalArgumentException("Expected tag ${BERTags.BIT_STRING}, is: ${src.tag}")
            if (src.length == 0) return Asn1BitString(0, byteArrayOf())
            return Asn1BitString(src.content[0], src.content.sliceArray(1..<src.content.size))
        }
    }

    override fun encodeToTlv() = Asn1Primitive(BERTags.BIT_STRING, byteArrayOf(numPaddingBits, *rawBytes))
}