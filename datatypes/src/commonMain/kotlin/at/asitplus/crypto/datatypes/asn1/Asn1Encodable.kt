package at.asitplus.crypto.datatypes.asn1

interface Asn1Encodable<A : Asn1Element> {
    fun encodeToTlv(): A
}

interface Asn1Decodable<A : Asn1Element, T : Asn1Encodable<A>> {
    fun decodeFromTlv(src: A): T
}
