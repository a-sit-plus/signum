package at.asitplus.signum.indispensable.asn1

import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.Asn1Element.Tag.Template.Companion.withClass
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
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
    internal val tlv: TLV,
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
        return if (this is Asn1Primitive) {
            (this.content contentEquals other.content)
        } else {
            this as Asn1Structure
            other as Asn1Structure
            children == other.children
        }
    }

    companion object {
        /**
         * Convenience method to directly parse a HEX-string representation of DER-encoded data
         * @throws [Throwable] all sorts of errors on invalid input
         */
        @Throws(Throwable::class)
        fun decodeFromDerHexString(derEncoded: String) =
            Asn1Element.parse(derEncoded.replace(Regex("\\s"), "").trim().decodeToByteArray(Base16))
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
        children?.fold(0) { acc, extendedTlv -> acc + extendedTlv.overallLength } ?: tlv.contentLength
    }

    /**
     * Total number of bytes required to represent the ths element, when encoding to ASN.1.
     */
    val overallLength by lazy { length + tlv.tag.encodedTagLength + encodedLength.size }

    protected open val content by lazy { tlv.content }

    val tag by lazy { tlv.tag }

    val derEncoded: ByteArray by lazy {
        children?.fold(byteArrayOf()) { acc, extendedTlv -> acc + extendedTlv.derEncoded }
            ?.let { byteArrayOf(*tlv.tag.encodedTag, *it.size.encodeLength(), *it) }
            ?: byteArrayOf(*tlv.tag.encodedTag, *encodedLength, *tlv.content)
    }

    override fun toString(): String = "(tag=${tlv.tag}" +
            ", length=${length}" +
            ", overallLength=${overallLength}" +
            (children?.let { ", children=$children" } ?: ", content=${
                content.encodeToString(Base16 {
                    lineBreakInterval = 0;encodeToLowercase = false
                })
            }") +
            ")"


    fun prettyPrint() = prettyPrint(0)

    protected open fun prettyPrint(indent: Int): String = "(tag=${tlv.tag}" +
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

    /**
     * Convenience function to cast this element to an [Asn1Primitive]
     * @throws Asn1StructuralException if this element is not a primitive
     */
    @Throws(Asn1StructuralException::class)
    fun asPrimitive() = thisAs<Asn1Primitive>()

    /**
     * Convenience function to cast this element to an [Asn1Structure]
     * @throws Asn1StructuralException if this element is not a structure
     */
    @Throws(Asn1StructuralException::class)
    fun asStructure() = thisAs<Asn1Structure>()

    /**
     * Convenience function to cast this element to an [Asn1Sequence]
     * @throws Asn1StructuralException if this element is not a sequence
     */
    @Throws(Asn1StructuralException::class)
    fun asSequence() = thisAs<Asn1Sequence>()

    /**
     * Convenience function to cast this element to an [Asn1Set]
     * @throws Asn1StructuralException if this element is not a set
     */
    @Throws(Asn1StructuralException::class)
    fun asSet() = thisAs<Asn1Set>()

    /**
     * Convenience function to cast this element to an [Asn1ExplicitlyTagged]
     * @throws Asn1StructuralException if this element is not an explicitly tagged structure
     */
    @Throws(Asn1StructuralException::class)
    fun asExplicitlyTagged() = thisAs<Asn1ExplicitlyTagged>()

    /**
     * Convenience function to cast this element to an [Asn1EncapsulatingOctetString]
     * @throws Asn1StructuralException if this element is not an octet string containing a valid ASN.1 structure
     */
    @Throws(Asn1StructuralException::class)
    fun asEncapsulatingOctetString() = thisAs<Asn1EncapsulatingOctetString>()

    /**
     * Convenience function to cast this element to an [Asn1PrimitiveOctetString]
     * @throws Asn1StructuralException if this element is not an octet string containing raw data
     */
    @Throws(Asn1StructuralException::class)
    fun asPrimitiveOctetString() = thisAs<Asn1PrimitiveOctetString>()

    @Throws(Asn1StructuralException::class)
    private inline fun <reified T : Asn1Element> thisAs(): T =
        (this as? T)
            ?: throw Asn1StructuralException("${this::class.simpleName} cannot be reinterpreted as ${T::class.simpleName}.")


    /**
     * Creates a new implicitly tagged ASN.1 Element from this ASN.1 Element.
     * NOTE: The [TagClass] of the provided [tag] will be used! If you want the result to have [TagClass.CONTEXT_SPECIFIC],
     * use `element withImplicitTag (tag withClass TagClass.CONTEXT_SPECIFIC)`!. If a CONSTRUCTED Tag is applied to an ASN.1 Primitive,
     * the CONSTRUCTED bit is overridden and set to zero.
     */
    inline infix fun withImplicitTag(tag: Tag): Asn1Element = when (this) {
        is Asn1Structure -> {
            if (tag.isConstructed) Asn1CustomStructure(
                children,
                tag.tagValue,
                tag.tagClass,
                sort = isSorted
            ) else Asn1CustomStructure.asPrimitive(children, tag.tagValue, tag.tagClass)
        }

        is Asn1Primitive -> Asn1Primitive(tag without CONSTRUCTED, content)
    }

    /**
     * Creates a new implicitly tagged ASN.1 Element from this ASN.1 Element.
     * Sets the class of the resulting structure to [TagClass.CONTEXT_SPECIFIC]
     */
    inline infix fun withImplicitTag(tagValue: ULong) = withImplicitTag(tagValue withClass TagClass.CONTEXT_SPECIFIC)


    /**
     * Creates a new implicitly tagged ASN.1 Element from this ASN.1 Structure.
     * If the provided [template]'s tagClass is not set, the class of the resulting structure defaults to [TagClass.CONTEXT_SPECIFIC].
     * If a CONSTRUCTED Tag is applied to an ASN.1 Primitive, the CONSTRUCTED bit is overridden and set to zero.
     */
    inline infix fun withImplicitTag(template: Tag.Template) = when (this) {
        is Asn1Structure -> (this as Asn1Structure).withImplicitTag(
            Tag(
                tagValue = template.tagValue,
                tagClass = template.tagClass ?: TagClass.CONTEXT_SPECIFIC,
                constructed = template.constructed ?: tag.isConstructed
            )
        )

        is Asn1Primitive -> Asn1Primitive(
            Tag(template.tagValue, tagClass = template.tagClass ?: TagClass.CONTEXT_SPECIFIC, constructed = false),
            content
        )
    }


    @Serializable
    @ConsistentCopyVisibility
    data class Tag private constructor(
        val tagValue: ULong, val encodedTagLength: Int,
        @Serializable(with = ByteArrayBase64Serializer::class) val encodedTag: ByteArray
    ) : Comparable<Tag> {
        private constructor(values: Triple<ULong, Int, ByteArray>) : this(values.first, values.second, values.third)
        constructor(derEncoded: ByteArray) : this(
            derEncoded.iterator().decodeTag().let { Triple(it.first, it.second.size, derEncoded) }
        )

        constructor(tagValue: ULong, constructed: Boolean, tagClass: TagClass = TagClass.UNIVERSAL) : this(
            encode(
                tagClass,
                constructed,
                tagValue
            )
        )

        companion object {
            private fun encode(tagClass: TagClass, constructed: Boolean, tagValue: ULong): ByteArray {
                val derEncoded: ByteArray =
                    if (tagValue <= 30u) {
                        byteArrayOf(tagValue.toUByte().toByte())
                    } else {
                        byteArrayOf(0b11111, *tagValue.toAsn1VarInt())
                    }

                derEncoded[0] = derEncoded[0].toUByte()
                    .let { if (constructed) (it or BERTags.CONSTRUCTED) else it }
                    .let { it or tagClass.berTag }
                    .toByte()
                return derEncoded
            }

            val SET = Tag(tagValue = BERTags.SET.toULong(), constructed = true)
            val SEQUENCE = Tag(tagValue = BERTags.SEQUENCE.toULong(), constructed = true)

            val NULL = Tag(tagValue = BERTags.ASN1_NULL.toULong(), constructed = false)
            val BOOL = Tag(tagValue = BERTags.BOOLEAN.toULong(), constructed = false)
            val INT = Tag(tagValue = BERTags.INTEGER.toULong(), constructed = false)
            val OID = Tag(tagValue = BERTags.OBJECT_IDENTIFIER.toULong(), constructed = false)

            val OCTET_STRING = Tag(tagValue = BERTags.OCTET_STRING.toULong(), constructed = false)
            val BIT_STRING = Tag(tagValue = BERTags.BIT_STRING.toULong(), constructed = false)

            val STRING_UTF8 = Tag(tagValue = BERTags.UTF8_STRING.toULong(), constructed = false)
            val STRING_UNIVERSAL = Tag(tagValue = BERTags.UNIVERSAL_STRING.toULong(), constructed = false)
            val STRING_IA5 = Tag(tagValue = BERTags.IA5_STRING.toULong(), constructed = false)
            val STRING_BMP = Tag(tagValue = BERTags.BMP_STRING.toULong(), constructed = false)
            val STRING_T61 = Tag(tagValue = BERTags.T61_STRING.toULong(), constructed = false)
            val STRING_PRINTABLE = Tag(tagValue = BERTags.PRINTABLE_STRING.toULong(), constructed = false)
            val STRING_NUMERIC = Tag(tagValue = BERTags.NUMERIC_STRING.toULong(), constructed = false)
            val STRING_VISIBLE = Tag(tagValue = BERTags.VISIBLE_STRING.toULong(), constructed = false)

            val TIME_GENERALIZED = Tag(tagValue = BERTags.GENERALIZED_TIME.toULong(), constructed = false)
            val TIME_UTC = Tag(tagValue = BERTags.UTC_TIME.toULong(), constructed = false)

        }

        val tagClass by lazy {
            checkNotNull(TagClass.fromByte(encodedTag.first()).getOrNull()) {
                "An Illegal Tag class has been found. This should be impossible!"
            }
        }

        val isConstructed get() = encodedTag.first().toUByte().isConstructed()

        internal val isExplicitlyTagged get() = isConstructed && tagClass == TagClass.CONTEXT_SPECIFIC

        override fun toString(): String =
            "${tagClass.let { if (it == TagClass.UNIVERSAL) "" else it.name + " " }}${tagValue}${if (isConstructed) " CONSTRUCTED" else ""}" +
                    (" (=${encodedTag.encodeToString(Base16)})")

        /**
         * As per ITU-T X.680 8824-1 8.6
         *
         */
        override fun compareTo(other: Tag) = EncodedTagComparator.compare(this, other)

        private object EncodedTagComparator : Comparator<Tag> {
            override fun compare(a: Tag, b: Tag): Int {
                val lenCompare = a.encodedTagLength.compareTo(b.encodedTagLength)
                if (lenCompare != 0) return lenCompare

                val firstCompare =
                    a.encodedTag.first().toUByte().toUShort().compareTo(b.encodedTag.first().toUByte().toUShort())
                if (firstCompare != 0) return firstCompare


                //now, we're down to numbers
                return a.tagValue.compareTo(b.tagValue)
            }

        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Tag) return false
            if (!encodedTag.contentEquals(other.encodedTag)) return false

            return true
        }

        override fun hashCode(): Int = encodedTag.contentHashCode()

        /**
         * creates a new Tag from this object, overriding the class. Useful for implicitTagging (see [Asn1Structure.withImplicitTag])
         */
        infix fun withClass(tagClass: TagClass) =
            Tag(this.tagValue, tagClass = tagClass, constructed = this.isConstructed)

        /**
         * creates a new Tag from this object, negating the passed property. Useful for implicitTagging (see [Asn1Structure.withImplicitTag]).
         * This is a NOOP for tag that don't have this bit set.
         */
        infix fun without(negated: TagProperty): Tag = when (negated) {
            CONSTRUCTED -> Tag(this.tagValue, tagClass = this.tagClass, constructed = false)
        }

        /**
         * A tag with optional tagClass and optional constructed indicator. Used for ASN.1 builder DSL
         */
        class Template(val tagValue: ULong, val tagClass: TagClass?, val constructed: Boolean?) {

            /**
             * Creates a new tag template from this template, negating the passed property
             */
            inline infix fun without(negated: TagProperty) = when (negated) {
                is CONSTRUCTED -> Template(this.tagValue, this.tagClass, false)
            }

            companion object {
                /**
                 * Convenience function to construct a tag template from an ULong tag value and class
                 */
                inline infix fun ULong.withClass(tagClass: TagClass) =
                    Template(tagValue = this, tagClass = tagClass, constructed = null)

                /**
                 * Convenience function to construct a tag from an ULong tag value and property
                 */
                inline infix fun ULong.without(negated: TagProperty) = when (negated) {
                    is CONSTRUCTED -> Template(tagValue = this, tagClass = null, constructed = false)
                }

            }

        }
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
sealed class Asn1Structure(tag: Tag, children: List<Asn1Element>?, sort: Boolean = false) :
    Asn1Element(TLV(tag, byteArrayOf()), if (!sort) children else children?.sortedBy { it.tag }) {

    /**
     * Whether this structure sorts child nodes or keeps them as-is.
     * This **should** be true for SET and SET OF, but is set to false for SET and SET OF elements parsed
     * from DER-encoded structures, because this has a chance of altering the structure for non-conforming DER-encoded
     * structures.
     */
    val isSorted: Boolean = sort

    public override val children: List<Asn1Element>
        get() = super.children!!

    private var index = 0

    /**
     * Returns the next child held by this structure. Useful for iterating over its children when parsing complex structures.
     * @throws [Asn1StructuralException] if no more children are available
     */
    @Throws(Asn1StructuralException::class)
    fun nextChild() =
        catching { children[index++] }.getOrElse { throw Asn1StructuralException("No more content left") }

    /**
     * Exception-free version of [nextChild]
     */
    fun nextChildOrNull() = catching { nextChild() }.getOrNull()

    /**
     * Returns `true` if more children can be retrieved by [nextChild]. `false` otherwise
     */
    fun hasMoreChildren() = children.size > index

    /**
     * Returns the current child (useful when iterating over this structure's children)
     */
    fun peek() = if (!hasMoreChildren()) null else children[index]

}

/**
 * Explicit ASN.1 Tag. Can contain any number of [children]
 */
class Asn1ExplicitlyTagged
/**
 * @param tag the ASN.1 Tag to be used will be properly encoded to have [BERTags.CONSTRUCTED] and
 * [BERTags.CONTEXT_SPECIFIC] bits set)
 * @param children the child nodes to be contained in this tag
 *
 */
internal constructor(tag: ULong, children: List<Asn1Element>) :
    Asn1Structure(Tag(tag, constructed = true, tagClass = TagClass.CONTEXT_SPECIFIC), children) {


    /**
     * Returns this [Asn1ExplicitlyTagged] children, if its tag matches [tag]
     *
     * @throws Asn1TagMismatchException if the tag does not match
     */
    @Throws(Asn1TagMismatchException::class)
    fun verifyTag(explicitTag: Tag): List<Asn1Element> {
        if (this.tag != explicitTag) throw Asn1TagMismatchException(explicitTag, this.tag)
        return this.children
    }

    /**
     * Returns this [Asn1ExplicitlyTagged] children, if its tag matches [tagNumber]
     *
     * @throws Asn1TagMismatchException if the tag does not match
     */
    @Throws(Asn1TagMismatchException::class)
    fun verifyTag(tagNumber: ULong): List<Asn1Element> = verifyTag(Asn1.ExplicitTag(tagNumber))

    /**
     * Exception-free version of [verifyTag]
     */
    fun verifyTagOrNull(tagNumber: ULong) = catching { verifyTag(tagNumber) }.getOrNull()

    /**
     * Exception-free version of [verifyTag]
     */
    fun verifyTagOrNull(explicitTag: Tag) = catching { verifyTag(explicitTag) }.getOrNull()

    override fun toString() = "Tagged" + super.toString()
    override fun prettyPrint(indent: Int) = (" " * indent) + "Tagged" + super.prettyPrint(indent + 2)
}

/**
 * ASN.1 SEQUENCE 0x30 ([BERTags.SEQUENCE] OR [BERTags.CONSTRUCTED])
 * @param children the elements to put into this sequence
 */
class Asn1Sequence internal constructor(children: List<Asn1Element>) :
    Asn1Structure(Tag.SEQUENCE, children) {

    init {
        if (!tag.isConstructed) throw IllegalArgumentException("An ASN.1 Structure must have a CONSTRUCTED tag")

    }

    override fun toString() = "Sequence" + super.toString()
    override fun prettyPrint(indent: Int) = (" " * indent) + "Sequence" + super.prettyPrint(indent + 2)
}

/**
 * ASN1 structure (i.e. containing child nodes) with custom tag
 */
class Asn1CustomStructure private constructor(
    tag: Tag, children: List<Asn1Element>, sort: Boolean
) :
    Asn1Structure(tag, children) {
    /**
     * ASN.1 CONSTRUCTED with custom tag
     * @param children the elements to put into this sequence
     * @param tag the custom tag to use
     * @param tagClass the tag class to use for this custom tag. defaults to [TagClass.UNIVERSAL]
     * @param sort whether to sort the passed child nodes. defaults to false
     */
    constructor(
        children: List<Asn1Element>,
        tag: ULong,
        tagClass: TagClass = TagClass.UNIVERSAL,
        sort: Boolean = false
    ) : this(Tag(tag, constructed = true, tagClass), children, sort)

    /**
     * ASN.1 CONSTRUCTED with custom tag
     * @param children the elements to put into this sequence
     * @param tag the custom tag to use
     * @param tagClass the tag class to use for this custom tag. defaults to [TagClass.UNIVERSAL]
     * @param sort whether to sort the passed child nodes. defaults to false
     */
    constructor(
        children: List<Asn1Element>,
        tag: UByte,
        tagClass: TagClass = TagClass.UNIVERSAL,
        sort: Boolean = false
    ) : this(children, tag.toULong(), tagClass, sort)


    override val content: ByteArray by lazy {
        if (!tag.isConstructed)
            children.fold(byteArrayOf()) { acc, asn1Element -> acc + asn1Element.derEncoded }
        else super.content
    }

    override fun toString() = "${tag.tagClass}" + super.toString()

    override fun prettyPrint(indent: Int) =
        (" " * indent) + tag.tagClass + " ${tag.tagValue} " + super.prettyPrint(indent + 2)

    companion object {
        /**
         * ASN.1 Structure encoded as an ASN.1 Primitive (similar to OCTET STRING containing a valid ASN.1 Structure) with custom tag
         * @param children the elements to put into this sequence
         * @param tag the custom tag to use
         * @param tagClass the tag class to use for this custom tag. defaults to [TagClass.UNIVERSAL]
         * @param sort whether to sort the passed childr nodes. defaults to false
         */
        fun asPrimitive(
            children: List<Asn1Element>,
            tag: ULong,
            tagClass: TagClass = TagClass.UNIVERSAL,
            sort: Boolean = false
        ) =
            Asn1CustomStructure(Tag(tag, constructed = false, tagClass), children, sort)
    }
}

/**
 * ASN.1 OCTET STRING 0x04 ([BERTags.OCTET_STRING]) containing an [Asn1Element]
 * @param children the elements to put into this sequence
 */
@Suppress("SERIALIZER_TYPE_INCOMPATIBLE")
@Serializable(with = Asn1EncodableSerializer::class)
class Asn1EncapsulatingOctetString(children: List<Asn1Element>) :
    Asn1Structure(Tag.OCTET_STRING, children),
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
class Asn1PrimitiveOctetString(content: ByteArray) : Asn1Primitive(Tag.OCTET_STRING, content),
    Asn1OctetString<Asn1PrimitiveOctetString> {

    override val content: ByteArray get() = super.content

    override fun unwrap() = this

    override fun toString() = "OCTET STRING " + super.toString()

    override fun prettyPrint(indent: Int) = (" " * indent) + "OCTET STRING Primitive" + tlv.toString().substring(3)
}


/**
 * ASN.1 SET 0x31 ([BERTags.SET] OR [BERTags.CONSTRUCTED])
 */
open class Asn1Set private constructor(children: List<Asn1Element>?, dontSort: Boolean) :
    Asn1Structure(Tag.SET, children, !dontSort) {

    /**
     * @param children the elements to put into this set. will be automatically sorted by tag
     */
    internal constructor(children: List<Asn1Element>?) : this(children, false)

    init {
        if (!tag.isConstructed) throw IllegalArgumentException("An ASN.1 Structure must have a CONSTRUCTED tag")

    }

    override fun toString() = "Set" + super.toString()


    override fun prettyPrint(indent: Int) = (" " * indent) + "Set" + super.prettyPrint(indent + 2)

    companion object {
        /**
         * Explicitly discard DER requirements and DON'T sort children. Useful when parsing Structures which might not
         * conform to DER
         */
        internal fun fromPresorted(children: List<Asn1Element>) = Asn1Set(children, true)
    }
}

/**
 * ASN.1 SET OF 0x31 ([BERTags.SET] OR [BERTags.CONSTRUCTED])
 * @param children the elements to put into this set. will be automatically checked to have the same tag and sorted by value
 * @throws Asn1Exception if children are using different tags
 */
class Asn1SetOf @Throws(Asn1Exception::class) internal constructor(children: List<Asn1Element>?) :
    Asn1Set(children?.let {
        if (it.any { elem -> elem.tag != it.first().tag }) throw Asn1Exception("SET OF must only contain elements of the same tag")
        it.sortedBy { it.tag.encodedTag.encodeToString(Base16) } //TODO this is inefficient
    })

/**
 * ASN.1 primitive. Hold o children, but [content] under [tag]
 */
open class Asn1Primitive(tag: Tag, content: ByteArray) : Asn1Element(TLV(tag, content), null) {
    init {
        if (tag.isConstructed) throw IllegalArgumentException("A primitive cannot have a CONSTRUCTED tag")
    }

    override fun toString() = "Primitive" + super.toString()

    constructor(tagValue: ULong, content: ByteArray) : this(Tag(tagValue, false), content)

    constructor(tagValue: UByte, content: ByteArray) : this(tagValue.toULong(), content)

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


@Throws(IllegalArgumentException::class)
internal fun Int.encodeLength(): ByteArray {
    require(this >= 0)
    return when {
        (this < 0x80) -> byteArrayOf(this.toByte()) /* short form */
        else -> { /* long form */
            val length = this.toUnsignedByteArray()
            val lengthLength = length.size
            check(lengthLength < 0x80)
            byteArrayOf((lengthLength or 0x80).toByte(), *length)
        }
    }
}