@file:Suppress("UNCHECKED_CAST")

package at.asitplus.signum.indispensable.asn1

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.Asn1Element.Tag

/**
 * Interface providing methods to encode to ASN.1
 */
interface Asn1Encodable<A : Asn1Element> {

    /**
     * Encodes the implementing object into an [A]
     * @throws Asn1Exception in case an illegal ASN.1 Object was to be constructed
     */
    @Throws(Asn1Exception::class)
    fun encodeToTlv(): A

    /**
     * Exception-free version of [encodeToTlv]
     */
    fun encodeToTlvOrNull() = catching { encodeToTlv() }.getOrNull()

    /**
     * Safe version of [encodeToTlv], wrapping the result into a [KmmResult]
     */
    fun encodeToTlvSafe() = catching { encodeToTlv() }

    /**
     * Convenience function to directly get the DER-encoded representation of the implementing object
     */
    @Throws(Asn1Exception::class)
    fun encodeToDer() = encodeToTlv().derEncoded

    /**
     * Exception-free version of [encodeToDer]
     */
    fun encodeToDerOrNull() = catching { encodeToDer() }.getOrNull()

    /**
     * Safe version of [encodeToDer], wrapping the result into a [KmmResult]
     */
    fun encodeToDerSafe() = catching { encodeToDer() }

    /**
     * Creates a new implicitly tagged ASN.1 Element from this ASN.1 Element.
     * NOTE: The [TagClass] of the provided [tag] will be used! If you want the result to have [TagClass.CONTEXT_SPECIFIC],
     * also invoke `tag withClass TagClass.CONTEXT_SPECIFIC`!. If a CONSTRUCTED Tag is applied to an ASN.1 Primitive,
     * the CONSTRUCTED bit is overridden and set to zero
     */
    infix fun withImplicitTag(tag: Tag) = encodeToTlv().withImplicitTag(tag)

    /**
     * Creates a new implicitly tagged  ASN.1 Element from this ASN.1 Element.
     * Sets the class of the resulting structure to [TagClass.CONTEXT_SPECIFIC]
     */
    infix fun withImplicitTag(tagValue: ULong) = encodeToTlv().withImplicitTag(tagValue)

    /**
     * Creates a new implicitly tagged ASN.1 Element from this ASN.1 Structure.
     * If the provided [template]'s tagClass is not set, the class of the resulting structure defaults to [TagClass.CONTEXT_SPECIFIC].
     * If a CONSTRUCTED Tag is applied to an ASN.1 Primitive, the CONSTRUCTED bit is overridden and set to zero
     */
    infix fun withImplicitTag(template: Tag.Template) = encodeToTlv().withImplicitTag(template)
}

/**
 * Interface providing convenience methods to decode from ASN.1.
 * Especially useful when companion objects of classes implementing [Asn1Encodable] implement it.
 */
interface Asn1Decodable<A : Asn1Element, T : Asn1Encodable<A>> {
    /**
     * Processes an [A], parsing it into an instance of [T]
     * @throws Asn1Exception if invalid data is provided.
     * Allows overriding the tag, if it deviates from the element's default tag.
     * Specify [tagOverride] for verifying implicitly tagged elements (and better not override this function).
     * @throws Asn1Exception
     */
    @Throws(Asn1Exception::class)
    fun decodeFromTlv(src: A, tagOverride: Asn1Element.Tag? = null): T {
        verifyTag(src, tagOverride)
        return doDecode(src)
    }

    /**
     * Actual element-specific decoding function. By default, this is invoked after [verifyTag]
     * @throws Asn1Exception
     */
    @Throws(Asn1Exception::class)
    fun doDecode(src: A): T

    @Throws(Asn1TagMismatchException::class)
    fun verifyTag(src: A, tagOverride: Asn1Element.Tag?) {
        val expected = tagOverride ?: return
        if (src.tag != expected)
            throw Asn1TagMismatchException(expected, src.tag)
    }

    /**
     * Exception-free version of [decodeFromTlv]
     */
    fun decodeFromTlvOrNull(src: A, tagOverride: Asn1Element.Tag? = null) =
        catching { decodeFromTlv(src, tagOverride) }.getOrNull()

    /**
     * Safe version of [decodeFromTlv], wrapping the result into a [KmmResult]
     */
    fun decodeFromTlvSafe(src: A, tagOverride: Asn1Element.Tag? = null) =
        catching { decodeFromTlv(src, tagOverride) }

    /**
     * Convenience method, directly DER-decoding a byte array to [T]
     * @throws Asn1Exception if invalid data is provided
     */
    @Throws(Asn1Exception::class)
    fun decodeFromDer(src: ByteArray, tagOverride: Asn1Element.Tag? = null): T =
        decodeFromTlv(Asn1Element.parse(src) as A, tagOverride)

    /**
     * Exception-free version of [decodeFromDer]
     */
    fun decodeFromDerOrNull(src: ByteArray, tagOverride: Asn1Element.Tag? = null) =
        catching { decodeFromDer(src, tagOverride) }.getOrNull()

    /**
     * Safe version of [decodeFromDer], wrapping the result into a [KmmResult]
     */
    fun decodeFromDerSafe(src: ByteArray, tagOverride: Asn1Element.Tag? = null) =
        catching { decodeFromDer(src, tagOverride) }
}
