package at.asitplus.crypto.datatypes.asn1

import kotlinx.serialization.Transient

interface Asn1Encodable<A : Asn1Element> {
    fun encodeToTlv(): A

    @Transient
    val derEncoded get() = encodeToTlv().derEncoded
}

interface Asn1Decodable<A : Asn1Element, T : Asn1Encodable<A>> {
    fun decodeFromTlv(src: A): T

    fun derDecode(src: ByteArray): T = decodeFromTlv(Asn1Element.parse(src) as A)

}
