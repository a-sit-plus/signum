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
     * Defaults to [encodeToDer]
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


private const val FENCE_PREFIX_BEGIN = "-----BEGIN "
private const val FENCE_PREFIX_END = "-----END "
private const val FENCE_SUFFIX = "-----"

/**-----BEGIN [PemEncodable.ebString]-----*/
private val PemEncodable<*>.preEB: String get() = "$FENCE_PREFIX_BEGIN${this.ebString}$FENCE_SUFFIX"

/**-----END [PemEncodable.ebString]-----*/
private val PemEncodable<*>.postEB: String get() = "$FENCE_PREFIX_END${this.ebString}$FENCE_SUFFIX"

/**
 * Encodes this [PemEncodable] into a PEM-encoded string
 */
@OptIn(ExperimentalEncodingApi::class)
fun PemEncodable<*>.encodeToPEM(): KmmResult<String> = catching {
    "$preEB\n" + Base64.Mime.encode(binaryEncodePayload()).lines().joinToString("").chunked(64)
        .joinToString(separator = "\n", postfix = "\n") + postEB
}

/**
 * Decodes a PEM-encoded string into [T]
 */
@OptIn(ExperimentalEncodingApi::class)
fun <A : Asn1Element, T : PemEncodable<A>> PemDecodable<A, T>.decodeFromPem(src: String): KmmResult<T> = catching {
    src.lineSequence()
        .map(String::trim)
        .dropWhile { !(it.startsWith(FENCE_PREFIX_BEGIN) && it.endsWith(FENCE_SUFFIX)) }
        .iterator()
        .run {
            require(hasNext()) { "No encapsulation boundary found" }
            val firstLine = next()
            val ebString = firstLine.substring(FENCE_PREFIX_BEGIN.length, firstLine.length - FENCE_SUFFIX.length)
            val b64data = StringBuilder()
            while (hasNext()) {
                val line = next()
                if (line.startsWith(FENCE_PREFIX_END) && line.endsWith(FENCE_SUFFIX)) {
                    val afterEbString = line.substring(FENCE_PREFIX_END.length, line.length - FENCE_SUFFIX.length)
                    require(afterEbString == ebString) { "Boundary string mismatch: $ebString vs $afterEbString" }
                    return@run binaryDecodePayload(ebString, Base64.Mime.decode(b64data.toString()))
                }
                b64data.append(line)
            }
            throw IllegalArgumentException("End of string reached while parsing (no encapsulation terminator?)")
        }
}