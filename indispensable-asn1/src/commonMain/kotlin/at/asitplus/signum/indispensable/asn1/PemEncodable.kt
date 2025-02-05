package at.asitplus.signum.indispensable.asn1

import at.asitplus.KmmResult
import at.asitplus.catching
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.jvm.JvmInline

/**
 * Specialization of [Asn1Encodable], able to produce PEM-encoded strings
 * as per [RFC 1421](https://datatracker.ietf.org/doc/html/rfc1421#section-4.4).
 * Use in tandem with [PemDecodable].
 */
interface PemEncodable<A : Asn1Element> : Asn1Encodable<A> {

    /**
     * Encapsulation boundary string.
     * Will be automatically fenced.
     */
    val canonicalPEMBoundary: String
}

private sealed interface PemDecoder<out T> {
    @JvmInline value class Real<out T>(val fn: (ByteArray)->T): PemDecoder<T>
    data object Default: PemDecoder<Nothing>
    companion object {
        inline operator fun <T> invoke(noinline fn: ((ByteArray)->T)?) = when (fn) {
            null -> Default
            else -> Real(fn)
        }
    }
}

/**
 * Specialization of [Asn1Decodable], able to parse PEM-encoded strings
 * as per [RFC 1421](https://datatracker.ietf.org/doc/html/rfc1421).
 * Use in tandem with [PemEncodable].
 */
abstract class PemDecodable<A : Asn1Element, out T : PemEncodable<A>>
    private constructor(private val decoders: Map<String, PemDecoder<T>>)
    : Asn1Decodable<A, T>
{

    constructor(vararg ebStrings: String) : this(ebStrings.associateWith { PemDecoder.Default })
    constructor(vararg decoders: Pair<String, ((ByteArray)->T)?>) : this(decoders.associate { it.first to PemDecoder(it.second) })

    /** Decodes a PEM-encoded string into [T] */
    fun decodeFromPem(src: String): KmmResult<T> = catching {
        src.lineSequence()
            .map(String::trim)
            .dropWhile { !(it.startsWith(FENCE_PREFIX_BEGIN) && it.endsWith(FENCE_SUFFIX)) }
            .iterator()
            .let {
                require(it.hasNext()) { "No encapsulation boundary found" }
                val firstLine = it.next()
                val ebString = firstLine.substring(FENCE_PREFIX_BEGIN.length, firstLine.length - FENCE_SUFFIX.length)
                val decoder: PemDecoder<T> = decoders.getOrElse(ebString)
                    { throw IllegalArgumentException("Unknown encapsulation boundary string $ebString") }
                val b64data = StringBuilder()
                while (it.hasNext()) {
                    val line = it.next()
                    if (line.startsWith(FENCE_PREFIX_END) && line.endsWith(FENCE_SUFFIX)) {
                        val afterEbString = line.substring(FENCE_PREFIX_END.length, line.length - FENCE_SUFFIX.length)
                        require(afterEbString == ebString) { "Boundary string mismatch: $ebString vs $afterEbString" }
                        @OptIn(ExperimentalEncodingApi::class)
                        return@let Base64.Mime.decode(b64data.toString()).let { data -> when(decoder) {
                            is PemDecoder.Default -> decodeFromDer(data)
                            is PemDecoder.Real<T> -> decoder.fn(data)
                        }}
                    }
                    b64data.append(line)
                }
                throw IllegalArgumentException("End of string reached while parsing (no encapsulation terminator?)")
            }
    }
}


private const val FENCE_PREFIX_BEGIN = "-----BEGIN "
private const val FENCE_PREFIX_END = "-----END "
private const val FENCE_SUFFIX = "-----"

/**-----BEGIN [PemEncodable.canonicalPEMBoundary]-----*/
private val PemEncodable<*>.preEB: String get() = "$FENCE_PREFIX_BEGIN${this.canonicalPEMBoundary}$FENCE_SUFFIX"

/**-----END [PemEncodable.canonicalPEMBoundary]-----*/
private val PemEncodable<*>.postEB: String get() = "$FENCE_PREFIX_END${this.canonicalPEMBoundary}$FENCE_SUFFIX"

/**
 * Encodes this [PemEncodable] into a PEM-encoded string
 */
@OptIn(ExperimentalEncodingApi::class)
fun PemEncodable<*>.encodeToPEM(): KmmResult<String> = catching {
    "$preEB\n" + Base64.Mime.encode(encodeToDer()).lines().joinToString("").chunked(64)
        .joinToString(separator = "\n", postfix = "\n") + postEB
}
