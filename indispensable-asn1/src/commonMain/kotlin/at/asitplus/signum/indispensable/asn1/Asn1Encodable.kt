@file:Suppress("UNCHECKED_CAST")

package at.asitplus.signum.indispensable.asn1

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.Asn1Element.Tag
import at.asitplus.signum.indispensable.asn1.encoding.parse

/**
 * Interface providing methods to encode to ASN.1
 */
interface Asn1Encodable<out A : Asn1Element> {

    /**
     * Encodes the implementing object into an [A]
     * @throws Asn1Exception in case an illegal ASN.1 Object was to be constructed
     */
    @Throws(Asn1Exception::class)
    fun encodeToTlv(): A

    /**
     * Exception-free version of [encodeToTlv]
     */
    fun encodeToTlvOrNull() = catchingUnwrapped { encodeToTlv() }.getOrNull()

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
    fun encodeToDerOrNull() = catchingUnwrapped { encodeToDer() }.getOrNull()

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

    /**
     * shorthand for [Asn1Element.prettyPrint], hence, a call to this function encodes this encodable to an [Asn1Element],
     * holds int in memory, pretty prints it, and discards it.
     * This characteristic may be relevant in memory-constrained environments.
     */
    fun prettyPrint(): String = encodeToTlv().prettyPrint()
}

/**
 * Interface providing convenience methods to decode from ASN.1.
 * Especially useful when companion objects of classes implementing [Asn1Encodable] implement it.
 */
interface Asn1Decodable<A : Asn1Element, out T : Asn1Encodable<A>> {
    /**
     * Processes an [A], parsing it into an instance of [T]
     * @throws Asn1Exception if invalid data is provided.
     * Specify [assertTag] for verifying implicitly tagged elements' tags (and better not override this function).
     * @throws Asn1Exception
     */
    @Throws(Asn1Exception::class)
    fun decodeFromTlv(src: A, assertTag: Asn1Element.Tag? = null, requireFullConsumption: Boolean = true): T {
        verifyTag(src, assertTag)
        return doDecode(src).also {
            if (requireFullConsumption && src is Asn1Structure) {
                runRethrowing {
                    require(!src.hasMoreChildren()) { "Trailing data found in ASN.1 structure" }
                }
            }
        }
    }

    /**
     * Actual element-specific decoding function. By default, this is invoked after [verifyTag]
     * @throws Asn1Exception
     */
    @Throws(Asn1Exception::class)
    fun doDecode(src: A): T

    /**
     * Specify [assertTag] for verifying implicitly tagged elements' tags (and better not override this function).
     * @throws Asn1TagMismatchException
     */
    @Throws(Asn1TagMismatchException::class)
    fun verifyTag(src: A, assertTag: Asn1Element.Tag?) {
        val expected = assertTag ?: return
        if (src.tag != expected)
            throw Asn1TagMismatchException(expected, src.tag)
    }

    /**
     * Exception-free version of [decodeFromTlv]
     */
    fun decodeFromTlvOrNull(src: A, assertTag: Asn1Element.Tag? = null) =
        catchingUnwrapped { decodeFromTlv(src, assertTag) }.getOrNull()

    /**
     * Safe version of [decodeFromTlv], wrapping the result into a [KmmResult]
     */
    fun decodeFromTlvSafe(src: A, assertTag: Asn1Element.Tag? = null) =
        catching { decodeFromTlv(src, assertTag) }

    /**
     * Convenience method, directly DER-decoding a byte array to [T]
     * @throws Asn1Exception if invalid data is provided
     */
    @Throws(Asn1Exception::class)
    fun decodeFromDer(src: ByteArray, assertTag: Asn1Element.Tag? = null): T =
        decodeFromTlv(Asn1Element.parse(src) as A, assertTag)

    /**
     * Exception-free version of [decodeFromDer]
     */
    fun decodeFromDerOrNull(src: ByteArray, assertTag: Asn1Element.Tag? = null) =
        catchingUnwrapped { decodeFromDer(src, assertTag) }.getOrNull()

    /**
     * Safe version of [decodeFromDer], wrapping the result into a [KmmResult]
     */
    fun decodeFromDerSafe(src: ByteArray, assertTag: Asn1Element.Tag? = null) =
        catching { decodeFromDer(src, assertTag) }
}
