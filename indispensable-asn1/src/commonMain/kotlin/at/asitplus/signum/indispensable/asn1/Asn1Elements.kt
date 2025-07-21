@file:OptIn(ExperimentalStdlibApi::class)

package at.asitplus.signum.indispensable.asn1

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.Asn1Element.Tag.Template.Companion.withClass
import at.asitplus.signum.indispensable.asn1.encoding.*
import kotlinx.io.Buffer
import kotlinx.io.Sink
import kotlinx.io.readByteArray
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * Base ASN.1 data class. Can either be a primitive (holding a value), or a structure (holding other ASN.1 elements)
 */
sealed class Asn1Element(
    val tag: Tag
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null) return false
        if (other !is Asn1Element) return false
        if (tag != other.tag) return false
        if (this is Asn1Structure && other !is Asn1Structure) return false
        if (this is Asn1Primitive && other !is Asn1Primitive) return false
        return true

    }

    companion object {
        /**
         * Convenience method to directly parse a HEX-string representation of DER-encoded data.
         * Ignores and strips all whitespace.
         * @throws [Throwable] all sorts of errors on invalid input
         */
        @Throws(Throwable::class)
        @Deprecated("Misleading name", ReplaceWith("parseFromDerHexString(derEncoded)"), DeprecationLevel.ERROR)
        fun decodeFromDerHexString(derEncoded: String) = parseFromDerHexString(derEncoded)

        /**
         * Convenience method to directly parse a HEX-string representation of DER-encoded data.
         * Ignores and strips all whitespace.
         * @throws [Throwable] all sorts of errors on invalid input
         */
        @Throws(Throwable::class)
        fun parseFromDerHexString(derEncoded: String) =
            Asn1Element.parse(derEncoded.replace(Regex("\\s"), "").hexToByteArray(HexFormat.UpperCase))
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
    abstract val length: Int

    /**
     * Total number of bytes required to represent the ths element, when encoding to ASN.1.
     */
    val overallLength by lazy { length + tag.encodedTagLength + encodedLength.size }


    private val derEncodedLazy = lazy { Buffer().also { encodeTo(it) }.readByteArray() }

    /**
     * Lazily-evaluated DER-encoded representation of this ASN.1 element
     */
    val derEncoded: ByteArray by derEncodedLazy


    protected abstract fun doEncode(sink: Sink)
    internal fun encodeTo(sink: Sink) {
        if (derEncodedLazy.isInitialized()) {
            sink.write(derEncoded)
            return
        }
        doEncode(sink)
    }

    override fun toString(): String = prettyPrintHeader(0) +
            (if (this is Asn1Primitive) " " else "") +
            contentToString() +
            prettyPrintTrailer(0)

    protected abstract fun contentToString(): String

    fun prettyPrint() = prettyPrint(0)

    protected open fun prettyPrintHeader(indent: Int) =
        "(tag=${tag}" + ", length=${length}" + ", overallLength=${overallLength})"

    protected open fun prettyPrintTrailer(indent: Int) = ""
    protected abstract fun prettyPrintContents(indent: Int): String

    internal open fun prettyPrint(indent: Int): String =
        prettyPrintHeader(indent) + prettyPrintContents(indent) + prettyPrintTrailer(indent)


    protected operator fun String.times(op: Int): String = repeat(op)


    /**
     * Convenience method to directly produce an HEX string of this element's ASN.1 representation
     */
    fun toDerHexString(lineLen: Int? = null) = derEncoded.toHexString(HexFormat.UpperCase)
        .let { if (lineLen == null) it else it.chunked(lineLen).joinToString(separator = "\n") }


    /**
     * Convenience function to cast this element to an [Asn1Primitive]
     * @throws Asn1StructuralException if this element is not a primitive
     */
    @Throws(Asn1StructuralException::class)
    fun asPrimitive() = when (this) {
        //this absolutely needs to be a primitive here and copying is typically OK,
        //because this will be part of a parser pipeline that needs the raw bytes anyway
        is Asn1EncapsulatingOctetString -> Asn1PrimitiveOctetString(this.content)
        else -> thisAs<Asn1Primitive>()
    }

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
     * Convenience function to cast this element to an [Asn1OctetString]
     * @throws Asn1StructuralException if this element is not an octet string
     */
    @Throws(Asn1StructuralException::class)
    fun asOctetString() = thisAs<Asn1OctetString>()

    /**
     * Convenience function to cast this element to an [Asn1PrimitiveOctetString]
     * @throws Asn1StructuralException if this element is not an octet string containing raw data
     */
    @Throws(Asn1StructuralException::class)
    @Deprecated("Use asOctetString instead to avoid copying", ReplaceWith("asOctetString"), DeprecationLevel.ERROR)
    fun asPrimitiveOctetString() = when (this) {
        is Asn1EncapsulatingOctetString -> Asn1PrimitiveOctetString(this.content)
        else -> thisAs<Asn1PrimitiveOctetString>()
    }

    @Throws(Asn1StructuralException::class)
    private inline fun <reified T> thisAs(): T =
       (this as? T)
            ?: throw Asn1StructuralException("${this::class.simpleName} cannot be reinterpreted as ${T::class.simpleName}.")


    /**
     * Creates a new implicitly tagged ASN.1 Element from this ASN.1 Element.
     * NOTE: The [TagClass] of the provided [tag] will be used! If you want the result to have [TagClass.CONTEXT_SPECIFIC],
     * use `element withImplicitTag (tag withClass TagClass.CONTEXT_SPECIFIC)`!. If a CONSTRUCTED Tag is applied to an ASN.1 Primitive,
     * the CONSTRUCTED bit is overridden and set to zero.
     */
    @Suppress("NOTHING_TO_INLINE")
    inline infix fun withImplicitTag(tag: Tag): Asn1Element = when (this) {
        is Asn1Structure -> {
            if (tag.isConstructed) Asn1CustomStructure(
                children,
                tag.tagValue,
                tag.tagClass,
                sortChildren = false,
                shouldBeSorted = shouldBeSorted
            ) else Asn1CustomStructure.asPrimitive(
                children,
                tag.tagValue,
                tag.tagClass,
                sortChildren = false,
                shouldBeSorted = shouldBeSorted
            )
        }

        is Asn1Primitive -> Asn1Primitive(tag without CONSTRUCTED, content)
    }

    /**
     * Creates a new implicitly tagged ASN.1 Element from this ASN.1 Element.
     * Sets the class of the resulting structure to [TagClass.CONTEXT_SPECIFIC]
     */
    @Suppress("NOTHING_TO_INLINE")
    inline infix fun withImplicitTag(tagValue: ULong) = withImplicitTag(tagValue withClass TagClass.CONTEXT_SPECIFIC)


    /**
     * Creates a new implicitly tagged ASN.1 Element from this ASN.1 Structure.
     * If the provided [template]'s tagClass is not set, the class of the resulting structure defaults to [TagClass.CONTEXT_SPECIFIC].
     * If a CONSTRUCTED Tag is applied to an ASN.1 Primitive, the CONSTRUCTED bit is overridden and set to zero.
     */
    @Suppress("NOTHING_TO_INLINE")
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

    override fun hashCode(): Int = tag.hashCode()


    @ConsistentCopyVisibility
    data class Tag internal constructor(
        val tagValue: ULong,
        val encodedTag: ByteArray
    ) : Comparable<Tag> {

        //workaround because we cannot return two values or assign params in a destructured manner
        private constructor(decoded: Pair<ULong, ByteArray>) : this(decoded.first, decoded.second)

        /**
         * The length (in bytes) of this tag when encoded according to DER
         */
        val encodedTagLength: Int = encodedTag.size

        /**
         * Creates a copy of this tag, overriding [tagValue], but keeping [isConstructed] and [tagClass]
         */
        infix fun withNumber(number: ULong) = Tag(number, constructed = isConstructed, tagClass = tagClass)

        constructor(tagValue: ULong, constructed: Boolean, tagClass: TagClass = TagClass.UNIVERSAL) : this(
            tagValue, encode(tagClass, constructed, tagValue)
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

            @OptIn(ExperimentalObjCName::class)
            @ObjCName("ASN1_NULL") //workaround KT-33092
            val NULL = Tag(tagValue = BERTags.ASN1_NULL.toULong(), constructed = false)
            val BOOL = Tag(tagValue = BERTags.BOOLEAN.toULong(), constructed = false)
            val INT = Tag(tagValue = BERTags.INTEGER.toULong(), constructed = false)
            val REAL = Tag(tagValue = BERTags.REAL.toULong(), constructed = false)
            val OID = Tag(tagValue = BERTags.OBJECT_IDENTIFIER.toULong(), constructed = false)
            val ENUM = Tag(tagValue = BERTags.ENUMERATED.toULong(), constructed = false)

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
                    (" (=${encodedTag.toHexString(HexFormat.UpperCase)})")

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
            @Suppress("NOTHING_TO_INLINE")
            inline infix fun without(negated: TagProperty) = when (negated) {
                is CONSTRUCTED -> Template(this.tagValue, this.tagClass, false)
            }

            companion object {
                /**
                 * Convenience function to construct a tag template from an ULong tag value and class
                 */
                @Suppress("NOTHING_TO_INLINE")
                inline infix fun ULong.withClass(tagClass: TagClass) =
                    Template(tagValue = this, tagClass = tagClass, constructed = null)

                /**
                 * Convenience function to construct a tag from an ULong tag value and property
                 */
                @Suppress("NOTHING_TO_INLINE")
                inline infix fun ULong.without(negated: TagProperty) = when (negated) {
                    is CONSTRUCTED -> Template(tagValue = this, tagClass = null, constructed = false)
                }

            }

        }
    }
}

/**
 * asserts that this element's tag matches [tag].
 *
 * @throws Asn1TagMismatchException on failure
 */
@Throws(Asn1TagMismatchException::class)
inline fun <reified T : Asn1Element> T.assertTag(tag: Asn1Element.Tag): T {
    if (this.tag != tag) throw Asn1TagMismatchException(tag, this.tag)
    return this
}

/**
 * Asserts only the tag number, but neither class, nor CONSTRUCTED bit.
 * @see assertTag
 * @throws Asn1TagMismatchException on failure
 */
@Throws(Asn1TagMismatchException::class)
inline fun <reified T : Asn1Element> T.assertTag(tagNumber: ULong): T = assertTag(tag withNumber tagNumber)


/**
 * ASN.1 structure. Contains no data itself, but holds zero or more [children]
 */
sealed class Asn1Structure(
    /**
     * The tag identifying this structure
     */
    tag: Tag,

    /**
     * This structure's child elements
     */
    children: List<Asn1Element>,
    /**
     * Whether this structure sorts child nodes or keeps them as-is.
     * This **should** be true for SET and SET OF, but is set to false for SET and SET OF elements parsed
     * from DER-encoded structures, because this has a chance of altering the structure for non-conforming DER-encoded
     * structures.
     */
    sortChildren: Boolean,

    /**
     * Indicates whether this structure should sort their child nodes by default. This is true for SET and for
     * all custom structure that enforce SET semantics. Note that it is impossible to infer this property correctly when
     * parsing custom structures. Therefore, it has no impact on [equals].
     */
    val shouldBeSorted: Boolean
) :
    Asn1Element(tag), Iterable<Asn1Element> {

    val children: List<Asn1Element> = if (!sortChildren) children else children.sortedBy { it.tag }

    /**
     * indicated whether the structure's children are actually sorted.
     * This could be false for parsing non-compliant SETs, for example.
     */
    val isActuallySorted: Boolean by if (sortChildren) lazyOf(true) else lazy { children.sortedBy { it.tag } == children }

    private val backwardsCompatibilityIterator by lazy { iterator() }

    /**
     * Returns the next child held by this structure. Useful for iterating over its children when parsing complex structures.
     * @throws [Asn1StructuralException] if no more children are available
     *### Migration Examples:
     *
     * Using `decodeRethrowing`:
     * ```kotlin
     * val result = structure.decodeRethrowing {
     *     val child = next()
     *     // ...
     *     DecodedStructure(...)
     * }
     * ```
     *
     * Manual iteration:
     * ```kotlin
     * val iterator = structure.iterator()
     * while (iterator.hasNext()) {
     *     val child = iterator.next()
     *     // Process child
     * }
     * ```
     */
    @Deprecated(
        message = "Use an explicit iterator()",
        level = DeprecationLevel.ERROR
    )
    @Throws(Asn1StructuralException::class)
    fun nextChild() = backwardsCompatibilityIterator.next()

    /**
     * Exception-free version of [nextChild]
     *### Migration Examples:
     *
     * Using `decodeRethrowing`:
     * ```kotlin
     * val result = structure.decodeRethrowing {
     *     val child = nextOrNull()
     *     // ...
     *     DecodedStructure(...)
     * }
     * ```
     *
     * Manual iteration:
     * ```kotlin
     * val iterator = structure.iterator()
     * while (iterator.hasNext()) {
     *     val child = iterator.nextOrNull()
     *     // Process child
     * }
     * ```
     */
    @Deprecated(
        message = "Use an explicit iterator()",
        level = DeprecationLevel.ERROR
    )
    fun nextChildOrNull() = backwardsCompatibilityIterator.peek()?.also { backwardsCompatibilityIterator.next() }

    /**
     * Returns `true` if more children can be retrieved by [nextChild]. `false` otherwise
     * ### Migration Examples:
     *
     * Using `decodeRethrowing`:
     * ```kotlin
     * structure.decodeRethrowing {
     *     if (hasNext()) {
     *         // ...
     *     }
     *     DecodedStructure(...)
     * }
     * ```
     *
     * Manual iteration:
     * ```kotlin
     * val iterator = structure.iterator()
     * if (iterator.hasNext()) {
     *     // ...
     * }
     * ```
     */
    @Deprecated(
        message = "Use an explicit iterator()",
        level = DeprecationLevel.ERROR
    )
    fun hasMoreChildren() = backwardsCompatibilityIterator.hasNext()

    /**
     * Returns the current child or `null`, if there are no children left
     * (useful when iterating over this structure's children).
     * ### Migration Examples:
     *
     * Using `decodeRethrowing`:
     * ```kotlin
     * structure.decodeRethrowing {
     *     val decodedChild = peek()?.let {
     *         // Inspect or conditionally consume the child
     *         val child = next()
     *         // ...
     *     }
     *     DecodedStructure(...)
     * }
     * ```
     *
     * Manual iteration:
     * ```kotlin
     * val iterator = structure.iterator()
     * val child = iterator.peek()
     * if (child != null) {
     *     // Inspect child without consuming it
     * }
     * ```
     */
    @Deprecated(
        message = "Use an explicit iterator()",
        level = DeprecationLevel.ERROR
    )
    fun peek() = backwardsCompatibilityIterator.peek()

    override operator fun iterator() = Iterator(isForward = true)
    fun reverseIterator() = Iterator(isForward = false)

    /**
     * An iterator over a list of [Asn1Element] children within an ASN.1 structure
     * Designed for traversing ASN.1 components in decoding/parsing scenarios
     * */
    inner class Iterator internal constructor(
        /** Whether this is a forward iterator */
        val isForward: Boolean
    ): kotlin.collections.Iterator<Asn1Element> {

        /** Whether this is a reverse iterator */
        val isReverse get() = !isForward

        /** reference to the [Asn1Structure] this iterator belongs to*/
        val containingStructure: Asn1Structure get() = this@Asn1Structure

        /** The index of the last element returned by [next] */
        var currentIndex: Int =
            if (isForward) -1 else children.size
            private set

        /** The last element returned by [next]. Throws [NoSuchElementException] if [next] was not yet called. */
        val currentElement get() =
            try { children[currentIndex] }
            catch (x: IndexOutOfBoundsException) { throw NoSuchElementException(x.message) }

        private val step get() = if (isForward) 1 else -1

        private val nextIndex get() = currentIndex + step

        /**
         * Returns the next child held by this structure. Useful for iterating over its children when parsing complex structures.
         * @throws [NoSuchElementException] if no more children are available
         */
        override fun next() {
            currentIndex = nextIndex
            return currentElement
        }

        /**
         * Exception-free version of [next]
         */
        fun nextOrNull() = if (hasNext()) next() else null

        /**
         * Returns `true` if more children can be retrieved by [next]. `false` otherwise
         */
        override fun hasNext() = if (isForward) (nextIndex < children.size) else (nextIndex >= 0)

        /**
         * Returns the next child that would be returned by a call to [next] without advancing to iterator.
         * If there are no more children, returns `null`.
         */
        fun peek() = if (hasNext()) children[nextIndex] else null

        /**
         * Returns an iterator with reversed direction.
         * Current iteration position is preserved.
         */
        fun reversed(): Iterator =
            Iterator(isForward = !isForward).also { it.currentIndex = this.currentIndex }
    }

    /**
     * Decodes the content of this ASN.1 structure using the provided [decoder] lambda.
     * This function gives a convenient way to decode ASN.1 structures by exposing an
     * iterator over the structure's children to the [decoder] lambda. Optionally, it enforces that
     * all children must be consumed. Use [decodeRethrowing] to automatically and consistently wrap exceptions
     * thrown during decoding in [Asn1Exception]s.
     */
    fun <T> decodeAs(requireFullConsumption: Boolean = true, decoder: Iterator.() -> T): T {
        val it = iterator()
        val result = it.decoder()
        if (requireFullConsumption && it.hasNext())
            throw Asn1StructuralException("Trailing data found in ASN.1 structure")
        return result
    }


    override val length: Int by lazy { children.fold(0) { acc, child -> acc + child.overallLength } }

    override fun doEncode(sink: Sink) {
        children.let { childElems ->
            sink.write(tag.encodedTag);
            sink.write(encodedLength);
            childElems.forEach { child -> child.encodeTo(sink) }
        }
    }

    override fun prettyPrintContents(indent: Int): String =
        children.joinToString(
            prefix = "\n" + (" " * indent) + "{\n",
            separator = "\n",
            postfix = "\n" + (" " * indent) + "}"
        ) { it.prettyPrint(indent + 2) }

    override fun contentToString(): String {
        val prefix = when {
            shouldBeSorted && isActuallySorted -> "SORTED"
            shouldBeSorted && !isActuallySorted -> "NON-COMPLIANT (UNSORTED)"
            else -> ""
        }
        return "$prefix, children=$children"
    }

    override fun hashCode() = 31 * super.hashCode() + children.hashCode()

    /**
     * the [shouldBeSorted] flag has no bearing on equals!
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Asn1Structure) return false
        if (!super.equals(other)) return false

        if (children != other.children) return false

        return true
    }
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
    Asn1Structure(
        Tag(tag, constructed = true, tagClass = TagClass.CONTEXT_SPECIFIC),
        children,
        sortChildren = false,
        shouldBeSorted = false
    ) {


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
    fun verifyTagOrNull(tagNumber: ULong) = catchingUnwrapped { verifyTag(tagNumber) }.getOrNull()

    /**
     * Exception-free version of [verifyTag]
     */
    fun verifyTagOrNull(explicitTag: Tag) = catchingUnwrapped { verifyTag(explicitTag) }.getOrNull()

    override fun prettyPrintHeader(indent: Int) = (" " * indent) + "Tagged" + super.prettyPrintHeader(indent)
}

/**
 * ASN.1 SEQUENCE 0x30 ([BERTags.SEQUENCE] OR [BERTags.CONSTRUCTED])
 * @param children the elements to put into this sequence
 */
class Asn1Sequence internal constructor(children: List<Asn1Element>) :
    Asn1Structure(Tag.SEQUENCE, children, sortChildren = false, shouldBeSorted = false) {

    init {
        if (!tag.isConstructed) throw IllegalArgumentException("An ASN.1 Structure must have a CONSTRUCTED tag")

    }

    override fun prettyPrintHeader(indent: Int) = (" " * indent) + "Sequence" + super.prettyPrintHeader(indent)
}

/**
 * ASN1 structure (i.e. containing child nodes) with custom tag
 */
class Asn1CustomStructure private constructor(
    tag: Tag, children: List<Asn1Element>, sortChildren: Boolean, shouldBeSorted: Boolean
) :
    Asn1Structure(tag, children, sortChildren, shouldBeSorted) {
    /**
     * ASN.1 CONSTRUCTED with custom tag
     * @param children the elements to put into this sequence
     * @param tag the custom tag to use
     * @param tagClass the tag class to use for this custom tag. defaults to [TagClass.UNIVERSAL]
     * @param sortChildren whether to sort the passed child nodes. defaults to false
     * @param shouldBeSorted whether the child nodes of this structure should be sorted according to this structure's definition.
     * Note that this information is lost when parsing custom structures!
     */
    constructor(
        children: List<Asn1Element>,
        tag: ULong,
        tagClass: TagClass = TagClass.UNIVERSAL,
        sortChildren: Boolean = false,
        shouldBeSorted: Boolean = false
    ) : this(Tag(tag, constructed = true, tagClass), children, sortChildren, shouldBeSorted)

    /**
     * ASN.1 CONSTRUCTED with custom tag
     * @param children the elements to put into this sequence
     * @param tag the custom tag to use
     * @param tagClass the tag class to use for this custom tag. defaults to [TagClass.UNIVERSAL]
     * @param sortChildren whether to sort the passed child nodes. defaults to false
     * @param shouldBeSorted whether the child nodes of this structure should be sorted according to this structure's definition.
     * Note that this information is lost when parsing custom structures!
     */
    constructor(
        children: List<Asn1Element>,
        tag: UByte,
        tagClass: TagClass = TagClass.UNIVERSAL,
        sortChildren: Boolean = false,
        shouldBeSorted: Boolean = false
    ) : this(children, tag.toULong(), tagClass, sortChildren, shouldBeSorted)


    /**
     * Raw byte DER-encoded representation of this custom structure's children.
     * This property is `null` **unless** the `CONSTRUCTED` flag of this structure's tag is overridden to `false`
     */
    val content: ByteArray? by lazy {
        if (!tag.isConstructed)
            children.fold(byteArrayOf()) { acc, asn1Element -> acc + asn1Element.derEncoded }
        else null
    }

    override fun toString() = "${tag.tagClass}" + super.toString()

    override fun prettyPrintHeader(indent: Int) =
        (" " * indent) + tag.tagClass +
                " ${tag.tagValue}" +
                (if (!tag.isConstructed) " PRIMITIVE" else "") +
                " (=${tag.encodedTag.toHexString(HexFormat.UpperCase)}), length=${length}" +
                ", overallLength=${overallLength}" +
                content?.let { " ${it.toHexString(HexFormat.UpperCase)}" }

    companion object {
        /**
         * ASN.1 Structure encoded as an ASN.1 Primitive (similar to OCTET STRING containing a valid ASN.1 Structure) with custom tag
         * @param children the elements to put into this sequence
         * @param tag the custom tag to use
         * @param tagClass the tag class to use for this custom tag. defaults to [TagClass.UNIVERSAL]
         * @param sortChildren whether to sort the passed child nodes. defaults to false
         */
        fun asPrimitive(
            children: List<Asn1Element>,
            tag: ULong,
            tagClass: TagClass = TagClass.UNIVERSAL,
            sortChildren: Boolean = false,
            shouldBeSorted: Boolean = false
        ) =
            Asn1CustomStructure(
                Tag(tag, constructed = false, tagClass),
                children,
                sortChildren,
                shouldBeSorted = shouldBeSorted
            )
    }
}

/**
 * ASN.1 OCTET STRING 0x04 ([BERTags.OCTET_STRING]) containing an [Asn1Element]
 * @param children the elements to put into this sequence
 */
@Suppress("SERIALIZER_TYPE_INCOMPATIBLE")
class Asn1EncapsulatingOctetString(children: List<Asn1Element>) :
    Asn1Structure(Tag.OCTET_STRING, children, sortChildren = false, shouldBeSorted = false),
    Asn1OctetString {
    override val content: ByteArray by lazy {
        children.fold(byteArrayOf()) { acc, asn1Element -> acc + asn1Element.derEncoded }
    }

    override fun equals(other: Any?): Boolean {
        if (other is Asn1PrimitiveOctetString) return this.content contentEquals other.content
        return super.equals(other)
    }

    override fun hashCode(): Int = content.contentHashCode()

    override fun prettyPrintHeader(indent: Int) =
        (" " * indent) + "OCTET STRING Encapsulating" + super.prettyPrintHeader(indent) + " " +
                content.toHexString(HexFormat.UpperCase)
}

/**
 * ASN.1 OCTET STRING 0x04 ([BERTags.OCTET_STRING]) containing arbitrary bytes
 * @param content the data to hold
 *
 * When parsing, you should NOT cast to this class.
 * Cast to [Asn1OctetString] instead.
 */
class Asn1PrimitiveOctetString(content: ByteArray) : Asn1Primitive(Tag.OCTET_STRING, content),
    Asn1OctetString {

    override fun equals(other: Any?): Boolean {
        if (other is Asn1EncapsulatingOctetString) return this.content contentEquals other.content
        return super.equals(other)
    }

    override fun hashCode(): Int = content.contentHashCode()

    override fun prettyPrintHeader(indent: Int) = (" " * indent) + "OCTET STRING " + super.prettyPrintHeader(0)
}


/**
 * ASN.1 SET 0x31 ([BERTags.SET] OR [BERTags.CONSTRUCTED])
 */
open class Asn1Set private constructor(children: List<Asn1Element>, dontSort: Boolean) :
    Asn1Structure(Tag.SET, children, !dontSort, shouldBeSorted = true) {

    /**
     * @param children the elements to put into this set. will be automatically sorted by tag
     */
    internal constructor(children: List<Asn1Element>) : this(children, false)

    init {
        if (!tag.isConstructed) throw IllegalArgumentException("An ASN.1 Structure must have a CONSTRUCTED tag")
    }


    override fun prettyPrintHeader(indent: Int) = (" " * indent) + "Set" + super.prettyPrintHeader(indent)

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
class Asn1SetOf @Throws(Asn1Exception::class) internal constructor(children: List<Asn1Element>) :
    Asn1Set(children.also { it ->
        if (it.any { elem -> elem.tag != it.first().tag }) throw Asn1Exception("SET OF must only contain elements of the same tag")
    })

/**
 * ASN.1 primitive. Holds no children, but [content] under [tag]
 */
open class Asn1Primitive(
    tag: Tag,
    /**
     * Raw data contained in this ASN.1 primitive in its encoded form. Requires decoding to interpret it
     */
    val content: ByteArray
) : Asn1Element(tag) {
    init {
        if (tag.isConstructed) throw IllegalArgumentException("A primitive cannot have a CONSTRUCTED tag")
    }

    override val length: Int get() = content.size
    override fun doEncode(sink: Sink) {
        sink.write(tag.encodedTag)
        sink.write(encodedLength)
        sink.write(content)
    }

    constructor(tagValue: ULong, content: ByteArray) : this(Tag(tagValue, false), content)

    constructor(tagValue: UByte, content: ByteArray) : this(tagValue.toULong(), content)

    override fun prettyPrintHeader(indent: Int) = (" " * indent) + "Primitive" + super.prettyPrintHeader(indent)

    override fun contentToString() = content.toHexString(HexFormat.UpperCase)
    override fun prettyPrintContents(indent: Int) = contentToString()


    override fun hashCode() = 31 * super.hashCode() + content.contentHashCode()
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Asn1Primitive) return false
        if (!super.equals(other)) return false

        if (!content.contentEquals(other.content)) return false

        return true
    }
}


/**
 * Interface describing an ASN.1 OCTET STRING.
 *
 * Signum will attempt to parse any ASN.1 OCTET STRING's content as ASN.1.
 * If this attempt succeeds, this will be an [Asn1EncapsulatingOctetString].
 * Otherwise, it will be an [Asn1PrimitiveOctetString].
 *
 * If you are expecting arbitrary bytes, [Asn1OctetString] is the correct type to look for.
 * (Your arbitrary bytes might inadvertently be valid ASN.1!)
 */
interface Asn1OctetString {

    /**
     * Raw data contained in this ASN.1 primitive in its encoded form. Requires decoding to interpret it.
     *
     * It makes sense to have this for both kinds of octet strings, since many intermediate processing steps don't care about semantics.
     */
    val content: ByteArray

    companion object {
        /** Constructs a new ASN.1 OCTET STRING primitive containing these bytes */
        operator fun invoke(bytes: ByteArray) =
            Asn1PrimitiveOctetString(bytes)
        /** Constructs a new ASN.1 OCTET STRING primitive encapsulating these children */
        operator fun invoke(children: List<Asn1Element>) =
            Asn1EncapsulatingOctetString(children)
    }
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

@Throws(IllegalArgumentException::class)
internal fun Sink.encodeLength(len: Long): Int {
    require(len >= 0)
    return when {
        (len < 0x80) -> writeByte(len.toByte()).run { 1 } /* short form */
        else -> { /* long form */
            val length = Buffer()
            val lengthLength = length.writeMagnitudeLong(len)
            check(lengthLength < 0x80)
            writeByte((lengthLength or 0x80).toByte())
            length.transferTo(this)
            1 + lengthLength
        }
    }
}