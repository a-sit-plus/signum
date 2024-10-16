package at.asitplus.signum.indispensable.asn1

import kotlinx.io.Buffer
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.toHexString
import kotlinx.io.readByteArray
import kotlinx.io.snapshot

internal sealed class TLV<T>(val tag: Asn1Element.Tag, val content: T) {

    val encodedContentLength by lazy { contentLength.encodeLength() }
    abstract val contentLength: Long
    val overallLength: Long by lazy { contentLength + tag.encodedTagLength + encodedContentLength.size }

    val tagClass: TagClass get() = tag.tagClass

    val isConstructed get() = tag.isConstructed

    val encodedTag get() = tag.encodedTag

    override fun equals(other: Any?): Boolean {
        if (other is TLV.Shallow || this is TLV.Shallow) throw IllegalStateException("Shallow TLVs may neve be compared")
        if (this === other) return true
        if (other == null) return false
        if (this::class != other::class) return false

        other as Immutable
        this as Immutable

        if (tag != other.tag) return false
        if (!content.contentEquals(other.content)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tag.hashCode()
        result = 31 * result + if(this is Shallow) content.hashCode() else (content as ByteArray).contentHashCode()
        return result
    }

    protected abstract val contentHexString: String

    override fun toString(): String {
        return "TLV(tag=$tag" +
                ", length=$contentLength" +
                ", overallLength=$overallLength" +
                ", content=$contentHexString)"
    }

    /**
     * Shallow TLV, containing a reference to the buffer it is based on. Once [content] is consumed, the underlying bytes are gone.
     */
    class Shallow(tag: Asn1Element.Tag, content: Buffer) : TLV<Buffer>(tag, content) {

        override val contentLength: Long by lazy { content.size }


        override fun equals(other: Any?): Boolean {
            throw IllegalStateException("Shallow TLVs may neve be compared")
        }


        override val contentHexString: String by lazy {
            @OptIn(ExperimentalStdlibApi::class)
            content.snapshot().toHexString(HexFormat.UpperCase)
        }

        /**
         * Deep-copies this shallow TLV into an [Immutable] one. Does not consume anything from [content]
         */
        fun deepCopy() = Immutable(tag, content.copy().readByteArray())

    }

    /**
     * Immutable TLV, containing a deep copy of the parsed bytes
     */
    class Immutable(tag: Asn1Element.Tag, content: ByteArray) : TLV<ByteArray>(tag, content) {

        override val contentLength: Long by lazy { content.size.toLong() }

        override val contentHexString: String by lazy {
            @OptIn(ExperimentalStdlibApi::class)
            content.toHexString(HexFormat.UpperCase)
        }
    }

}