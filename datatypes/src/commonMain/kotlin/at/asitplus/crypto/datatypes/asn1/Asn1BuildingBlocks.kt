package at.asitplus.crypto.datatypes.asn1

import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

sealed class ExtendedTlv protected constructor(private val tlv: TLV, open val children: List<ExtendedTlv>?) {

    val encodedLength by lazy { length.encodeLength() }
    val length: Int by lazy {
        children?.fold(0) { acc, extendedTlv -> acc + extendedTlv.overallLength } ?: tlv.length
    }

    val overallLength by lazy { length + 1 + encodedLength.size }

    val content by lazy { tlv.content }

    val tag by lazy { tlv.tag }

    val derEncoded: ByteArray by lazy {
        children?.fold(byteArrayOf()) { acc, extendedTlv -> acc + extendedTlv.derEncoded }
            ?.let { byteArrayOf(tlv.tag, *it.size.encodeLength(), *it) }
            ?: byteArrayOf(tlv.tag, *encodedLength, *tlv.content)
    }

    override fun toString(): String {
        return "(tag=0x${byteArrayOf(tag).encodeToString(Base16)}" +
                ", length=${length}" +
                ", overallLength=${overallLength}" +
                if (children != null) ", children=${children}" else ", content=${content.encodeToString(Base16)}" +
                        ")"
    }
}


sealed class Asn1Structure(tag: Int, children: List<ExtendedTlv>?) : ExtendedTlv(TLV(tag, byteArrayOf()), children){
    override val children: List<ExtendedTlv>
        get() = super.children!!
}

class Asn1Sequence(children: List<ExtendedTlv>) : Asn1Structure(DERTags.DER_SEQUENCE, children) {
    override fun toString() = "Sequence" + super.toString()
}

class Asn1Set(children: List<ExtendedTlv>?) : Asn1Structure(DERTags.DER_SET, children) {
    override fun toString() = "Set" + super.toString()
}

class Asn1Primitive(tag: Int, content: ByteArray) : ExtendedTlv(TLV(tag, content), null) {
    override fun toString() = "Primitive" + super.toString()
}

data class TLV(val tag: Byte, val content: ByteArray) {

    constructor(tag: Int, content: ByteArray) : this(tag.toByte(), content)

    val encodedLength by lazy { length.encodeLength() }
    val length by lazy { content.size }
    val overallLength by lazy { length + 1 + encodedLength.size }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as TLV

        if (tag != other.tag) return false
        if (!content.contentEquals(other.content)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tag.toInt()
        result = 31 * result + content.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "TLV(tag=0x${byteArrayOf(tag).encodeToString(Base16)}" +
                ", length=$length" +
                ", overallLength=$overallLength" +
                ", content=${content.encodeToString(Base16)})"
    }
}