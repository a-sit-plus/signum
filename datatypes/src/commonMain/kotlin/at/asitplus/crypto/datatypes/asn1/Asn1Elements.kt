package at.asitplus.crypto.datatypes.asn1

import at.asitplus.crypto.datatypes.asn1.DERTags.isExplicitTag
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Base ASN.1 data class. Can either be a primitive (holding a value), or a structure (holding other ASN.1 elements)
 */
@Serializable(with = Asn1EncodableSerializer::class)
sealed class Asn1Element(
    protected val tlv: TLV,
    protected open val children: List<Asn1Element>?
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null) return false
        if (other !is Asn1Element) return false
        if (tag != other.tag) return false
        if (!content.contentEquals(other.content)) return false
        if (this is Asn1Structure && other !is Asn1Structure) return false
        if (this is Asn1Primitive && other !is Asn1Primitive) return false
        if (this is Asn1Primitive) {
            return (this.content contentEquals other.content)
        } else {
            this as Asn1Structure
            other as Asn1Structure
            return children == other.children
        }
    }

    companion object {
        /**
         * Convenience method to directly parse a HEX-string representation of DER-encoded data
         * @throws [Throwable] all sorts of errors on invalid input
         */
        @Throws(Throwable::class)
        fun decodeFromDerHexString(derEncoded: String) = Asn1Element.parse(derEncoded.decodeToByteArray(Base16))
    }

    /**
     * Length (already properly encoded into a byte array for writing as ASN.1) of the contained data.
     * For a primitive, this is just the size of the held bytes.
     * For a structure, it is the sum of the number of bytes needed to encode all held child nodes.
     */
    val encodedLength by lazy { length.encodeLength() }

    /**
     * Length (as a plain `Int` to work with it in code) of the contained data.
     * For a primitive, this is just the size of the held bytes.
     * For a structure, it is the sum of the number of bytes needed to encode all held child nodes.
     */
    val length: Int by lazy {
        children?.fold(0) { acc, extendedTlv -> acc + extendedTlv.overallLength } ?: tlv.length
    }

    /**
     * Total number of bytes required to represent the ths element, when encoding to ASN.1.
     */
    val overallLength by lazy { length + 1 + encodedLength.size }

    protected open val content by lazy { tlv.content }

    val tag by lazy { tlv.tag }

    val derEncoded: ByteArray by lazy {
        children?.fold(byteArrayOf()) { acc, extendedTlv -> acc + extendedTlv.derEncoded }
            ?.let { byteArrayOf(tlv.tag.toByte(), *it.size.encodeLength(), *it) }
            ?: byteArrayOf(tlv.tag.toByte(), *encodedLength, *tlv.content)
    }

    override fun toString(): String = "(tag=0x${byteArrayOf(tag.toByte()).encodeToString(Base16)}" +
            ", length=${length}" +
            ", overallLength=${overallLength}" +
            (children?.let { ", children=$children" } ?: ", content=${
                content.encodeToString(Base16 {
                    lineBreakInterval = 0;encodeToLowercase = false
                })
            }") +
            ")"


    fun prettyPrint() = prettyPrint(0)

    protected open fun prettyPrint(indent: Int): String = "(tag=0x${byteArrayOf(tag.toByte()).encodeToString(Base16)}" +
            ", length=${length}" +
            ", overallLength=${overallLength}" +
            ((children?.joinToString(
                prefix = ")\n" + (" " * indent) + "{\n",
                separator = "\n",
                postfix = "\n" + (" " * indent) + "}"
            ) { it.prettyPrint(indent + 2) }) ?: ", content=${
                content.encodeToString(Base16 {
                    lineBreakInterval = 0;encodeToLowercase = false
                })
            })")


    protected operator fun String.times(op: Int): String {
        var s = this
        kotlin.repeat(op) { s += this }
        return s
    }

    /**
     * Convenience method to directly produce an HEX string of this element's ANS.1 representation
     */
    fun toDerHexString(lineLen: Byte? = null) = derEncoded.encodeToString(Base16 {
        lineLen?.let {
            lineBreakInterval = lineLen
        }
    })

    override fun hashCode(): Int {
        var result = tlv.hashCode()
        result = 31 * result + (children?.hashCode() ?: 0)
        return result
    }
}

object Asn1EncodableSerializer : KSerializer<Asn1Element> {
    override val descriptor = PrimitiveSerialDescriptor("Asn1Encodable", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Asn1Element {
        return Asn1Element.parse(decoder.decodeString().decodeToByteArray(Base16))
    }

    override fun serialize(encoder: Encoder, value: Asn1Element) {
        encoder.encodeString(value.derEncoded.encodeToString(Base16))
    }

}

/**
 * ASN.1 structure. Contains no data itself, but holds zero or more [children]
 */
sealed class Asn1Structure(tag: UByte, children: List<Asn1Element>?) :
    Asn1Element(TLV(tag, byteArrayOf()), children) {
    public override val children: List<Asn1Element>
        get() = super.children!!

    private var index = 0

    /**
     * Returns the next child held by this structure. Useful for iterating over its children when parsing complex structures.
     * @throws [IndexOutOfBoundsException] if no more children are available
     */
    @Throws(IndexOutOfBoundsException::class)
    fun nextChild() = children[index++]

    /**
     * Returns `true` if more children can be retrieved by [nextChild]. `false` otherwise
     */
    fun hasMoreChildren() = children.size > index

    /**
     * Returns the current child (useful when iterating over this structures children)
     */
    fun peek() = if (!hasMoreChildren()) null else children[index]
}

/**
 * Explicit ASN.1 Tag. Can contain any number of [children]
 */
class Asn1Tagged
/**
 * @param tag the ASN.1 Tag to be used (assumed to have [BERTags.CONSTRUCTED] and [BERTags.TAGGED] bits set)
 * @param children the child nodes to be contained in this tag
 *
 * @throws IllegalArgumentException is [tag] does not have [BERTags.CONSTRUCTED] and [BERTags.TAGGED] bits set
 */
@Throws(IllegalArgumentException::class)
constructor(tag: UByte, children: List<Asn1Element>) : Asn1Structure(tag, children) {

    init {
        if (!tag.isExplicitTag) throw IllegalArgumentException(
            "Tag 0x${byteArrayOf(tag.toByte()).encodeToString(Base16)} " +
                    "is not an explicit tag"
        )
    }

    override fun toString() = "Tagged" + super.toString()
    override fun prettyPrint(indent: Int) = (" " * indent) + "Tagged" + super.prettyPrint(indent + 2)
}

/**
 * ASN.1 SEQUENCE 0x30 ([DERTags.DER_SEQUENCE])
 * @param children the elements to put into this sequence
 */
class Asn1Sequence(children: List<Asn1Element>) : Asn1Structure(DERTags.DER_SEQUENCE, children) {
    override fun toString() = "Sequence" + super.toString()
    override fun prettyPrint(indent: Int) = (" " * indent) + "Sequence" + super.prettyPrint(indent + 2)
}

/**
 * ASN.1 OCTET STRING 0x04 ([BERTags.OCTET_STRING]) containing an [Asn1Element]
 * @param children the elements to put into this sequence
 */
class Asn1EncapsulatingOctetString(children: List<Asn1Element>) : Asn1Structure(BERTags.OCTET_STRING, children),
    Asn1OctetString<Asn1EncapsulatingOctetString> {
    override val content: ByteArray by lazy {
        children.fold(byteArrayOf()) { acc, asn1Element -> acc + asn1Element.derEncoded }
    }

    override fun unwrap() = this

    override fun toString() = "OCTET STRING Encapsulating" + super.toString()


    override fun prettyPrint(indent: Int) =
        (" " * indent) + "OCTET STRING Encapsulating" + super.prettyPrint(indent + 2)
}

/**
 * ASN.1 OCTET STRING 0x04 ([BERTags.OCTET_STRING]) containing data, which does not decode to an [Asn1Element]
 * @param content the data to hold
 */
class Asn1PrimitiveOctetString(content: ByteArray) : Asn1Primitive(BERTags.OCTET_STRING, content),
    Asn1OctetString<Asn1PrimitiveOctetString> {

    override val content: ByteArray get() = super.content

    override fun unwrap() = this

    override fun toString() = "OCTET STRING " + super.toString()

    override fun prettyPrint(indent: Int) = (" " * indent) + "OCTET STRING Primitive" + tlv.toString().substring(3)
}


/**
 * ASN.1 SET 0x30 ([DERTags.DER_SET])
 * @param children the elements to put into this set
 */
class Asn1Set(children: List<Asn1Element>?) : Asn1Structure(DERTags.DER_SET, children) {
    override fun toString() = "Set" + super.toString()


    override fun prettyPrint(indent: Int) = (" " * indent) + "Set" + super.prettyPrint(indent + 2)
}

/**
 * ASN.1 primitive. Hold o children, but [content] under [tag]
 */
open class Asn1Primitive(tag: UByte, content: ByteArray) : Asn1Element(TLV(tag, content), null) {
    override fun toString() = "Primitive" + super.toString()


    override fun prettyPrint(indent: Int) = (" " * indent) + "Primitive" + super.prettyPrint(indent)

    /**
     * Raw data contained in this ASN.1 primitive in its encoded form. Requires decoding to interpret it
     */
    public override val content: ByteArray
        get() = super.content
}


/**
 * Interface describing an ASN.1 OCTET STRING.
 * This is really more of a crutch, since an octet string is either an
 *
 *  * [Asn1Primitive] if it contains bytes, that cannot be interpreted as an ASN.1 Structure
 *  * [Asn1Structure] if it contains one or more valid [Asn1Element]s
 *
 *  This interface is implemented by [Asn1PrimitiveOctetString] for the former case and by [Asn1EncapsulatingOctetString] to cover the latter case
 *  Hence, [T] will either be [Asn1Primitive]/[Asn1PrimitiveOctetString] or [Asn1Structure]/[Asn1EncapsulatingOctetString]
 */
interface Asn1OctetString<T : Asn1Element> {

    /**
     * Raw data contained in this ASN.1 primitive in its encoded form. Requires decoding to interpret it.
     *
     * It makes sense to have this for both kinds of octet strings, since many intermediate processing steps don't care about semantics.
     */
    val content: ByteArray

    /**
     * Returns the actual type of this object inside the [Asn1Element] class hierarchy
     * [T] will either be [Asn1Primitive]/[Asn1PrimitiveOctetString] or [Asn1Structure]/[Asn1EncapsulatingOctetString]
     */
    fun unwrap(): T
}


data class TLV(val tag: UByte, val content: ByteArray) {

    val encodedLength by lazy { length.encodeLength() }
    val length by lazy { content.size }
    val overallLength by lazy { length + 1 + encodedLength.size }

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

private fun Int.encodeLength(): ByteArray {
    if (this < 128) {
        return byteArrayOf(this.toByte())
    }
    if (this < 0x100) {
        return byteArrayOf(0x81.toByte(), this.toByte())
    }
    if (this < 0x8000) {
        return byteArrayOf(0x82.toByte(), (this ushr 8).toByte(), this.toByte())
    }
    throw IllegalArgumentException("length $this")
}