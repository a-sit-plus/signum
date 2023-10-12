package at.asitplus.crypto.datatypes.asn1

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
     * Convenience method, directly DER-decoding a byte array to [T]
     * @throws [Throwable] of various sorts if invalid data is provided
     */
    @Throws(Throwable::class)
    fun derDecode(src: ByteArray): T = decodeFromTlv(Asn1Element.parse(src) as A)

}
