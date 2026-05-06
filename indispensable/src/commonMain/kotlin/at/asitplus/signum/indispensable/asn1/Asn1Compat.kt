package at.asitplus.signum.indispensable.asn1

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.awesn1.Asn1Decodable
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.encodeToDer

//TODO remove this file once
fun <A : Asn1Element> Asn1Encodable<A>.encodeToDerSafe(): KmmResult<ByteArray> =
    runCatching { encodeToDer() }.wrap()

fun <A : Asn1Element, T : Asn1Encodable<A>> Asn1Decodable<A, T>.decodeFromDerSafe(
    src: ByteArray,
    assertTag: Asn1Element.Tag? = null
): KmmResult<T> =
    runCatching { decodeFromDer(src, assertTag) }.wrap()

fun <A : Asn1Element, T : Asn1Encodable<A>> Asn1Decodable<A, T>.decodeFromTlvSafe(
    src: A,
    assertTag: Asn1Element.Tag? = null
): KmmResult<T> =
    runCatching { decodeFromTlv(src, assertTag) }.wrap()
