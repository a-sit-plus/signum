package at.asitplus.crypto.datatypes.asn1

import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

sealed class ExtendedTlv protected constructor(private val tlv: TLV, protected open val children: List<ExtendedTlv>?) {
    companion object

    val encodedLength by lazy { length.encodeLength() }
    val length: Int by lazy {
        children?.fold(0) { acc, extendedTlv -> acc + extendedTlv.overallLength } ?: tlv.length
    }

    val overallLength by lazy { length + 1 + encodedLength.size }

    val content by lazy { tlv.content }

    val tag by lazy { tlv.tag }

    val derEncoded: ByteArray by lazy {
        children?.fold(byteArrayOf()) { acc, extendedTlv -> acc + extendedTlv.derEncoded }
            ?.let { byteArrayOf(tlv.tag.toByte(), *it.size.encodeLength(), *it) }
            ?: byteArrayOf(tlv.tag.toByte(), *encodedLength, *tlv.content)
    }

    override fun toString(): String {
        return "(tag=0x${byteArrayOf(tag.toByte()).encodeToString(Base16)}" +
                ", length=${length}" +
                ", overallLength=${overallLength}" +
                if (children != null) ", children=${children}" else ", content=${content.encodeToString(Base16)}" +
                        ")"
    }
}


sealed class Asn1Structure(tag: UByte, children: List<ExtendedTlv>?) : ExtendedTlv(TLV(tag, byteArrayOf()), children) {
    public override val children: List<ExtendedTlv>
        get() = super.children!!

    private var index = 0
    fun nextChild() = children[index++]

    fun hasMoreChildren() = children.size > index

    fun peek() = children[index]
}

class Asn1Tagged(tag: UByte, val contained: ExtendedTlv) : ExtendedTlv(TLV(tag, byteArrayOf()), listOf(contained)) {
    override fun toString() = "Tagged" + super.toString()
}

class Asn1Sequence(children: List<ExtendedTlv>) : Asn1Structure(DERTags.DER_SEQUENCE, children) {
    override fun toString() = "Sequence" + super.toString()
}

class Asn1Set(children: List<ExtendedTlv>?) : Asn1Structure(DERTags.DER_SET, children) {
    override fun toString() = "Set" + super.toString()
}

class Asn1Primitive(tag: UByte, content: ByteArray) : ExtendedTlv(TLV(tag, content), null) {
    override fun toString() = "Primitive" + super.toString()
}

data class TLV(val tag: UByte, val content: ByteArray) {

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
        return "TLV(tag=0x${byteArrayOf(tag.toByte()).encodeToString(Base16)}" +
                ", length=$length" +
                ", overallLength=$overallLength" +
                ", content=${content.encodeToString(Base16)})"
    }
}