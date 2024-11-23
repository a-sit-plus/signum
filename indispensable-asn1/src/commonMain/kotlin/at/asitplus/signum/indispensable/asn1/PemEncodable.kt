package at.asitplus.signum.indispensable.asn1

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

interface PemEncodable<A : Asn1Element> : Asn1Encodable<A> {
    val ebString: String

    fun binaryEncodePayload() = encodeToDer()
}

interface PemDecodable<A : Asn1Element, T : PemEncodable<A>> : Asn1Decodable<A, T> {
    val ebString: String

    fun binaryDecodePayload(src: ByteArray) = decodeFromDer(src)
}

val PemEncodable<*>.preEB: String get() = "-----BEGIN $ebString-----"
val PemEncodable<*>.postEB: String get() = "-----END $ebString-----"

val PemDecodable<*, *>.preEB: String get() = "-----BEGIN $ebString-----"
val PemDecodable<*, *>.postEB: String get() = "-----END $ebString-----"

@OptIn(ExperimentalEncodingApi::class)
fun PemEncodable<*>.encodeToPEM(): String =
    "$preEB\n" + Base64.encode(binaryEncodePayload()).chunked(64).joinToString(separator = "\n", postfix = "\n") + postEB

@OptIn(ExperimentalEncodingApi::class)
fun <A : Asn1Element, T : PemEncodable<A>> PemDecodable<A, T>.decodeFromPem(src: String): T {
    val lines = src.lines()
    require(lines.first().trim() == preEB) { "PEM encoded String does not start with $preEB: ${lines.first()}" }
    require(lines.last().trim() == postEB) { "PEM encoded String does not end with $postEB: ${lines.last()}" }
    return binaryDecodePayload(Base64.decode(lines.slice(1..<lines.size - 1).joinToString(separator = "")))
}