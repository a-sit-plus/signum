package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.io.BitSet

/**
 * ASN.1 BIT STRING
 */
class Asn1BitString private constructor(
    /**
     * Number of bits needed to pad the bit string to a byte boundary
     */
    val numPaddingBits: Byte,

    /**
     * The raw bytes containing the bit string. The bits contained in [rawBytes] are laid out, as printed when calling
     * [BitSet.toBitString], right-padded with [numPaddingBits] many zero bits to the last byte boundary.
     *
     * The overall [Asn1Primitive.content] resulting from [encodeToTlv] is `byteArrayOf(numPaddingBits, *rawBytes)`
     */
    val rawBytes: ByteArray,
) :
    Asn1Encodable<Asn1Primitive> {


    /**
     * helper constructor to be able to use [fromBitSet]
     */
    private constructor(derValue: Pair<Byte, ByteArray>) : this(derValue.first, derValue.second)

    /**
     * Creates an ASN.1 BIT STRING from the provided bitSet.
     * The transformation to [rawBytes] and the calculation of [numPaddingBits] happens
     * immediately in the constructor. Hence, modifications to the source BitSet have no effect on the resulting [Asn1BitString].
     *
     * **BEWARE:** a bitset (as [BitSet] implements it) is, by definition only as long as the highest bit set!
     * Hence, trailing zeroes are **ALWAYS** stripped. If you require tailing zeroes, the easiest quick-and-dirty hack to accomplish this in general is as follows:
     *
     *  - set the last bit you require as tailing zero to one
     *  - call this constructor
     *  - flip the previously set bit back (this will be the lowest bit set in last byte of [rawBytes]).
     *
     * @param source the source [BitSet], which is discarded after [rawBytes] and [numPaddingBits] have been calculated
     */
    constructor(source: BitSet) : this(fromBitSet(source))

    /**
     * Transforms [rawBytes] and wraps into a [BitSet]. The last [numPaddingBits] bits are ignored.
     * This is a deep copy and mirrors the bits in every byte to match
     * the native bitset layout where bit any byte indices run in opposite direction.
     * Hence, modifications to the resulting bitset do not affect [rawBytes]
     *
     * Note: Tailing zeroes never count towards the length of the bitset
     *
     * See [BitSet] for more details on bit string representation vs memory layout.
     *
     */
    fun toBitSet(): BitSet {
        val size = rawBytes.size.toLong() * 8 - numPaddingBits
        val bitset = BitSet(size)
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

    companion object : Asn1TagVerifyingDecodable<Asn1BitString> {
        private fun fromBitSet(bitSet: BitSet): Pair<Byte, ByteArray> {
            val rawBytes = bitSet.bytes.map {
                var res = 0
                for (i in 0..7) {
                    if (it.toUByte().toInt() and (0x80 shr i) != 0) res = res or (0x01 shl i)
                }
                res.toUByte().toByte()
            }.toByteArray()
            return ((8 - (bitSet.length() % 8)) % 8).toByte() to rawBytes
        }

        @Throws(Asn1Exception::class)
        private fun decode(src: Asn1Primitive, tagOverride: TLV.Tag? = null): Asn1BitString {
            val expected = tagOverride ?: TLV.Tag(BERTags.BIT_STRING.toULong(), constructed = false)
            if (src.tag != expected)
                throw Asn1TagMismatchException(expected, src.tag)
            if (src.length == 0) return Asn1BitString(0, byteArrayOf())
            if (src.content.first() > 7) throw Asn1Exception("Number of padding bits < 7")
            return Asn1BitString(src.content[0], src.content.sliceArray(1..<src.content.size))
        }

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Primitive) = decodeFromTlv(src, null)

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Primitive, tagOverride: TLV.Tag?) = decode(src, tagOverride)
    }

    override fun encodeToTlv() = Asn1Primitive(BERTags.BIT_STRING.toULong(), byteArrayOf(numPaddingBits, *rawBytes))
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Asn1BitString

        if (numPaddingBits != other.numPaddingBits) return false
        if (!rawBytes.contentEquals(other.rawBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = numPaddingBits.toInt()
        result = 31 * result + rawBytes.contentHashCode()
        return result
    }
}