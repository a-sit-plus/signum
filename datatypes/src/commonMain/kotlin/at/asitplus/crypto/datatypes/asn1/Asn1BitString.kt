package at.asitplus.crypto.datatypes.asn1

import at.asitplus.crypto.datatypes.io.KmmBitSet

class Asn1BitString private constructor(val numPaddingBits: Byte, val rawBitString: ByteArray) :
    Asn1Encodable<Asn1Primitive> {


    fun toBitSet(): KmmBitSet {
        val size = rawBitString.size.toLong() * 8 - numPaddingBits
        val bitset = KmmBitSet(size)
        for (i in rawBitString.indices) {
            val bitOffset = i.toLong() * 8L
            for (bitIndex in 0..<8) {
                val globalIndex = bitOffset + bitIndex
                if (globalIndex == size) return bitset
                bitset[globalIndex] = (rawBitString[i].toInt() and (0x80 shr bitIndex) != 0)
            }
        }
        return bitset
    }

    companion object : Asn1Decodable<Asn1Primitive, Asn1BitString> {
        fun fromBitSet(bitSet: KmmBitSet): Asn1BitString {
            val rawBytes = bitSet.mapByte {
                var res = 0
                for (i in 0..7) {
                    if (it.toUByte().toInt() and (0x80 shr i) != 0) res = res or (0x01 shl i)//(0x80 shl (7 - i))
                }
                res.toUByte().toByte()
            }.toByteArray()
            return Asn1BitString(((8 - (bitSet.length() % 8)) % 8).toByte(), rawBytes)
        }

        override fun decodeFromTlv(src: Asn1Primitive): Asn1BitString {
            if (src.tag != BERTags.BIT_STRING) throw IllegalArgumentException("Expected tag ${BERTags.BIT_STRING}, is: ${src.tag}")
            if (src.length == 0) return Asn1BitString(0, byteArrayOf())
            return Asn1BitString(src.content[0], src.content.sliceArray(1..<src.content.size))
        }
    }

    override fun encodeToTlv() = Asn1Primitive(BERTags.BIT_STRING, byteArrayOf(numPaddingBits, *rawBitString))
}