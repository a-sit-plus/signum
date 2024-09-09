package at.asitplus.signum.indispensable.asn1

import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

internal data class TLV(val tag: Asn1Element.Tag, val content: ByteArray) {

    val encodedContentLength by lazy { contentLength.encodeLength() }
    val contentLength: Int by lazy { content.size }
    val overallLength: Int by lazy { contentLength + tag.encodedTagLength + encodedContentLength.size }

    val tagClass: TagClass get() = tag.tagClass

    val isConstructed get() = tag.isConstructed

    val encodedTag get() = tag.encodedTag

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null) return false
        if (this::class != other::class) return false

        other as TLV

        if (tag != other.tag) return false
        if (!content.contentEquals(other.content)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tag.hashCode()
        result = 31 * result + content.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "TLV(tag=$tag" +
                ", length=$contentLength" +
                ", overallLength=$overallLength" +
                ", content=${content.encodeToString(Base16)})"
    }

}