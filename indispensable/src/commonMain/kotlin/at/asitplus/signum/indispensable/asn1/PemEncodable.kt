package at.asitplus.signum.indispensable.asn1

import at.asitplus.KmmResult
import at.asitplus.catching
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Specialization of [Asn1Encodable], able to produce PEM-encoded strings
 * as per [RFC 1421](https://datatracker.ietf.org/doc/html/rfc1421#section-4.4).
 * Use in tandem with [PemDecodable].
 */
interface PemEncodable<A : Asn1Element> : Asn1Encodable<A> {

    /**
     * Encapsulation boundary string.
     * Will be automatically fenced.
     * Make sure it matches the corresponding [PemDecodable.ebString]!
     */
    val ebString: String

    /**
     * To be implemented for custom encoding of PEM-encoded payload.
     * Defaults to [encodeToDer].
     */
    @Throws(Throwable::class)
    fun binaryEncodePayload(): ByteArray = encodeToDer()
}

/**
 * Specialization of [Asn1Decodable], able to parse PEM-encoded strings
 * as per [RFC 1421](https://datatracker.ietf.org/doc/html/rfc1421).
 * Use in tandem with [PemEncodable].
 */
interface PemDecodable<A : Asn1Element, T : PemEncodable<A>> : Asn1Decodable<A, T> {

    /**
     * Encapsulation boundary string.
     * Will be automatically fenced.
     * Make sure it matches the corresponding [PemEncodable.ebString]!
     */
    val ebString: String

    /**
     * To be implemented for custom decoding of PEM-encoded payload.
     * Defaults to [decodeFromDer] and validates pre- and postEb
     */
    @Throws(Throwable::class)
    fun binaryDecodePayload(ebString: String, src: ByteArray): T {
        require(ebString == this.ebString) { "PEM encoded EB string does not match with ${this.ebString}: $ebString" }
        return decodeFromDer(src)
    }
}


private const val FENCE_PRE = "-----BEGIN "
private const val FENCE_POST = "-----END "
private const val FENCE_AFTER = "-----"

/**-----BEGIN [PemEncodable.ebString]-----*/
val PemEncodable<*>.preEB: String get() = "$FENCE_PRE$ebString$FENCE_AFTER"

/**-----END [PemEncodable.ebString]-----*/
val PemEncodable<*>.postEB: String get() = "$FENCE_POST$ebString$FENCE_AFTER"

/**-----BEGIN [PemDecodable.ebString]-----*/
val PemDecodable<*, *>.preEB: String get() = "$FENCE_PRE$ebString$FENCE_AFTER"

/**-----END [PemDecodable.ebString]-----*/
val PemDecodable<*, *>.postEB: String get() = "$FENCE_POST$ebString$FENCE_AFTER"

/**
 * Encodes this [PemEncodable] into a PEM-encoded string
 * If this [PemEncodable] also implements [Destroyable], setting [destroySource] to true destroys the source data
 */
@OptIn(ExperimentalEncodingApi::class)
fun PemEncodable<*>.encodeToPEM(destroySource: Boolean = false): KmmResult<String> = catching {
    val result = "$preEB\n" + Base64.encode(binaryEncodePayload()).chunked(64)
        .joinToString(separator = "\n", postfix = "\n") + postEB
    if (this is Destroyable && destroySource) destroy()
    result
}

/**
 * Reads the first line of the passed string and tries to extract the encapsulation boundary string
 */
@Throws(Throwable::class)
private fun PemDecodable<*, *>.peekEbString(src: String): String {
    val firstLine = src.lines().first()
    val lastLine = src.lines().last()
    require(firstLine.startsWith(FENCE_PRE)) { "PEM-encoded string must start with '$FENCE_PRE'! (mind the trailing space). First line: $firstLine" }
    require(firstLine.endsWith(FENCE_AFTER)) { "PEM-encoded string first line must end with '$FENCE_AFTER'! (without the trailing spaces). First line: $firstLine" }

    require(lastLine.startsWith(FENCE_POST)) { "PEM-encoded string last line start with '$FENCE_POST'! (mind the trailing space). Last line: $lastLine" }
    require(lastLine.endsWith(FENCE_AFTER)) { "PEM-encoded string must end with '$FENCE_AFTER'! (without the trailing spaces). Last line: $lastLine" }

    val ebString = firstLine.substring(FENCE_PRE.length, firstLine.length - FENCE_AFTER.length)
    val postEB = lastLine.substring(FENCE_POST.length, lastLine.length - FENCE_AFTER.length)
    require(ebString == postEB) {
        "PRE-EB and POST-EB strings differ: '$ebString' vs. '$postEB'"
    }

    return ebString
}

/**
 * Decodes a PEM-encoded string into [T]
 */
@OptIn(ExperimentalEncodingApi::class)
fun <A : Asn1Element, T : PemEncodable<A>> PemDecodable<A, T>.decodeFromPem(src: String): KmmResult<T> = catching {
    val lines = src.lines()
    binaryDecodePayload(peekEbString(src), Base64.decode(lines.slice(1..<lines.size - 1).joinToString(separator = "")))
}