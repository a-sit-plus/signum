package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.awesn1.Asn1Decodable
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.PemEncodable
import at.asitplus.awesn1.encoding.decodeFromDer as awesn1DecodeFromDer
import at.asitplus.awesn1.encoding.encodeToDer as awesn1EncodeToDer
import at.asitplus.awesn1.encodeToPem as awesn1EncodeToPem
import at.asitplus.catching

@Deprecated(
    "Moved to at.asitplus.awesn1.encodeToPem().",
    ReplaceWith("encodeToPem()", "at.asitplus.awesn1.encodeToPem")
)
fun PemEncodable.encodeToPEM(): KmmResult<String> = catching { awesn1EncodeToPem() }

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.encodeToDer().",
    ReplaceWith("encodeToDer()", "at.asitplus.awesn1.encoding.encodeToDer")
)
fun Asn1Encodable<*>.encodeToDer(): ByteArray = awesn1EncodeToDer()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeFromDer().",
    ReplaceWith(
        "decodeFromDer(this, src, assertTag)",
        "at.asitplus.awesn1.encoding.decodeFromDer"
    )
)
fun <A : Asn1Element, T : Asn1Encodable<A>> Asn1Decodable<A, T>.decodeFromDer(
    src: ByteArray,
    assertTag: Asn1Element.Tag? = null
): T = awesn1DecodeFromDer(src, assertTag)
