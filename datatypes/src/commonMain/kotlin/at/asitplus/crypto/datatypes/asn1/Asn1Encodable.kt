package at.asitplus.crypto.datatypes.asn1

import at.asitplus.crypto.datatypes.asn1.DERTags.toImplicitTag
import kotlinx.serialization.Transient

/**
 * Interface providing methods to encode to ASN.1
 */
interface Asn1Encodable<A : Asn1Element> {

    /**
     * Encodes the implementing object into an [A]
     */
    fun encodeToTlv(): A

    /**
     * Convenience property to directly get the DER-encoded representation of the implementing object
     */
    @Transient
    val derEncoded get() = encodeToTlv().derEncoded
}

/**
 * Interface providing convenience methods to decode from ASN.1.
 * Especially useful when companion objects of classes implementing [Asn1Encodable] implement it.
 */
interface Asn1Decodable<A : Asn1Element, T : Asn1Encodable<A>> {
    /**
     * Processes an [A], parsing it into an instance of [T]
     * @throws [Throwable] of various sorts if invalid data is provided
     */
    @Throws(Throwable::class)
    fun decodeFromTlv(src: A): T

    /**
     * Exception-free version of [decodeFromTlv]
     */
    fun decodeFromTlvOrNull(src: A) = runCatching { decodeFromTlv(src) }.getOrNull()

    /**
     * Convenience method, directly DER-decoding a byte array to [T]
     * @throws [Throwable] of various sorts if invalid data is provided
     */
    @Throws(Throwable::class)
    fun derDecode(src: ByteArray): T = decodeFromTlv(Asn1Element.parse(src) as A)

    /**
     * Exception-free version of [derDecode]
     */
    fun derDecodeOrNull(src: ByteArray) = runCatching { derDecode(src) }.getOrNull()
}

interface Asn1TagVerifyingDecodable<T : Asn1Encodable<Asn1Primitive>> : Asn1Decodable<Asn1Primitive, T> {

    /**
     * Same as [Asn1Decodable.decodeFromTlv], but allows overriding the tag, should the implementing class verify it.
     * Useful for implicit tagging, in which case you will want to call [at.asitplus.crypto.datatypes.asn1.DERTags.toImplicitTag] on [tagOverride].
     */
    @Throws(Throwable::class)
    fun decodeFromTlv(src: Asn1Primitive, tagOverride: UByte?): T

    /**
     * Exception-free version of [decodeFromTlv]
     */
    fun decodeFromTlvOrNull(src: Asn1Primitive, tagOverride: UByte?) =
        runCatching { decodeFromTlv(src, tagOverride) }.getOrNull()

    /**
     * Same as [Asn1Decodable.derDecode], but allows overriding the tag, should the implementing class verify it.
     * Useful for implicit tagging.
     */
    @Throws(Throwable::class)
    fun derDecode(src: ByteArray, tagOverride: UByte?): T =
        decodeFromTlv(Asn1Element.parse(src) as Asn1Primitive, tagOverride)

    /**
     * Exception-free version of [derDecode]
     */
    fun derDecodeOrNull(src: ByteArray, tagOverride: UByte?) = runCatching { derDecode(src, tagOverride) }.getOrNull()
}
