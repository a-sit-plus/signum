package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.io.encodeToDer
import at.asitplus.awesn1.io.parse
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import kotlinx.io.Sink
import kotlinx.io.Source
import kotlinx.serialization.SerializationException


/**
 * Interface providing methods to encode to ASN.1/DER using awesn1
 */
interface DerEncodable {
    /**
     * Encodes the implementing object into an [Asn1Element] through [der] serialization
     * @throws SerializationException in case an illegal ASN.1 Object was to be constructed
     */
    @Throws(SerializationException::class)
    fun encodeToTlv(der: Der = DER): Asn1Element
}

fun DerEncodable.encodeToDer(der: Der = DER): ByteArray = encodeToTlv(der).derEncoded
fun DerEncodable.encodeToDer(sink: Sink, der: Der = DER): Unit = encodeToTlv(der).encodeToDer(sink)


/**
 * Interface providing convenience methods to decode from ASN.1.
 * Especially useful when companion objects of classes implementing [DerEncodable] implement it.
 */
interface DerDecodable<out T : DerEncodable> {
    /**
     * Processes an [Asn1Element], parsing it into an instance of [T] through [der] serialization
     * @throws SerializationException if invalid data is provided.
     */
    @Throws(Asn1Exception::class)
    fun decodeFromTlv(src: Asn1Element, der: Der = DER): T
}


fun <T : DerEncodable> DerDecodable<T>.decodeFromDer(bytes: ByteArray, der: Der = DER): T =
    decodeFromTlv(Asn1Element.parse(bytes), der)
fun <T : DerEncodable> DerDecodable<T>.decodeFromDer(source: Source, der: Der = DER): T =
    decodeFromTlv(Asn1Element.parse(source), der)