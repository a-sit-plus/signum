package at.asitplus.crypto.datatypes.asn1

import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

data class ExtendedTlv(val tlv: TLV, val children: List<ExtendedTlv>) {

    val encodedLength by lazy { length.encodeLength() }
    val length: Int by lazy {
        if (children.isEmpty()) tlv.length
        else children.fold(0) { acc, extendedTlv -> acc + extendedTlv.overallLength }
    }

    val overallLength by lazy { length + 1 + encodedLength.size }

    val derEncoded: ByteArray by lazy {
        if (children.isEmpty()) byteArrayOf(tlv.tag, *encodedLength, *tlv.content)
        else {
            children.fold(byteArrayOf()) { acc, extendedTlv -> acc + extendedTlv.derEncoded }
                .let { byteArrayOf(tlv.tag, *it.size.encodeLength(), *it) }
        }
    }

    override fun toString(): String {
        return "ETLV(tag=0x${byteArrayOf(tlv.tag).encodeToString(Base16)}" +
                ", length=${tlv.length}" +
                ", overallLength=${tlv.overallLength}" +
                if (children.isNotEmpty()) ", children=${children}" else ", content=${tlv.content.encodeToString(Base16)}" +
                        ")"
    }
}

fun PrimitiveTLV(tag:Int, content: ByteArray)=ExtendedTlv(TLV(tag, content), emptyList())

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