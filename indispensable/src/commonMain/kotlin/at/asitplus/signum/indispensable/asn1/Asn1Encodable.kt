@file:Suppress("UNCHECKED_CAST")

package at.asitplus.signum.indispensable.asn1

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.toImplicitTag

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
}

/**
 * Interface providing convenience methods to decode from ASN.1.
 * Especially useful when companion objects of classes implementing [Asn1Encodable] implement it.
 */
interface Asn1Decodable<A : Asn1Element, T : Asn1Encodable<A>> {
    /**
     * Processes an [A], parsing it into an instance of [T]
     * @throws Asn1Exception if invalid data is provided
     */
    @Throws(Asn1Exception::class)
    fun decodeFromTlv(src: A): T

    /**
     * Exception-free version of [decodeFromTlv]
     */
    fun decodeFromTlvOrNull(src: A) = catching { decodeFromTlv(src) }.getOrNull()

    /**
     * Safe version of [decodeFromTlv], wrapping the result into a [KmmResult]
     */
    fun decodeFromTlvSafe(src: A) = catching { decodeFromTlv(src) }

    /**
     * Convenience method, directly DER-decoding a byte array to [T]
     * @throws Asn1Exception if invalid data is provided
     */
    @Throws(Asn1Exception::class)
    fun decodeFromDer(src: ByteArray): T = decodeFromTlv(Asn1Element.parse(src) as A)

    /**
     * Exception-free version of [decodeFromDerValue]
     */
    fun decodeFromDerOrNull(src: ByteArray) = catching { decodeFromDer(src) }.getOrNull()

    /**
     * Safe version of [decodeFromDerValue], wrapping the result into a [KmmResult]
     */
    fun decodeFromDerSafe(src: ByteArray) = catching { decodeFromDer(src) }
}

interface Asn1TagVerifyingDecodable<T : Asn1Encodable<Asn1Primitive>> :
    Asn1Decodable<Asn1Primitive, T> {

    /**
     * Same as [Asn1Decodable.decodeFromTlv], but allows overriding the tag, should the implementing class verify it.
     * Useful for implicit tagging, in which case you will want to call [at.asitplus.signum.indispensable.asn1.DERTags.toImplicitTag] on [tagOverride].
     * @throws Asn1Exception
     */
    @Throws(Asn1Exception::class)
    fun decodeFromTlv(src: Asn1Primitive, tagOverride: Asn1Element.Tag?): T

    /**
     * Exception-free version of [decodeFromTlv]
     */
    fun decodeFromTlvOrNull(src: Asn1Primitive, tagOverride: Asn1Element.Tag?) =
        catching { decodeFromTlv(src, tagOverride) }.getOrNull()

    /**
     * Safe version of [decodeFromTlv], wrapping the result into a [KmmResult]
     */
    fun decodeFromTlvSafe(src: Asn1Primitive, tagOverride: Asn1Element.Tag?) =
        catching { decodeFromTlv(src, tagOverride) }


    /**
     * Same as [Asn1Decodable.decodeFromDer], but allows overriding the tag, should the implementing class verify it.
     * Useful for implicit tagging.
     */
    @Throws(Asn1Exception::class)
    fun decodeFromDer(src: ByteArray, tagOverride: Asn1Element.Tag?): T =
        decodeFromTlv(Asn1Element.parse(src) as Asn1Primitive, tagOverride)

    /**
     * Exception-free version of [decodeFromDerValue]
     */
    fun decodeFromDerOrNull(src: ByteArray, tagOverride: Asn1Element.Tag?) =
        catching { decodeFromDer(src, tagOverride) }.getOrNull()

    /**
     * Safe version of [decodeFromDerValue], wrapping the result into a [KmmResult]
     */
    fun decodeFromDerSafe(src: ByteArray, tagOverride: Asn1Element.Tag?) = catching { decodeFromDer(src, tagOverride) }
}
