@file:Suppress("unused")

package at.asitplus.signum.indispensable.asn1

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.decodeFromPem as awesn1DecodeFromPem
import at.asitplus.awesn1.encodeToPem as awesn1EncodeToPem
import at.asitplus.awesn1.decodeFromTlvOrNull as awesn1DecodeFromTlvOrNull
import at.asitplus.awesn1.encoding.decodeFromDer as awesn1DecodeFromDer
import at.asitplus.awesn1.encoding.decodeFromDerOrNull as awesn1DecodeFromDerOrNull
import at.asitplus.awesn1.encoding.encodeToDer as awesn1EncodeToDer
import at.asitplus.awesn1.encoding.encodeToDerOrNull as awesn1EncodeToDerOrNull
import at.asitplus.awesn1.encoding.encodeToTlvOrNull as awesn1EncodeToTlvOrNull

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.encodeToTlvOrNull().",
    ReplaceWith("at.asitplus.awesn1.encoding.encodeToTlvOrNull(this)")
)
fun <A : Asn1Element> Asn1Encodable<A>.encodeToTlvOrNull(): A? = awesn1EncodeToTlvOrNull()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.encodeToDer().",
    ReplaceWith("at.asitplus.awesn1.encoding.encodeToDer(this)")
)
fun Asn1Encodable<*>.encodeToDer(): ByteArray = awesn1EncodeToDer()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.encodeToDerOrNull().",
    ReplaceWith("at.asitplus.awesn1.encoding.encodeToDerOrNull(this)")
)
fun Asn1Encodable<*>.encodeToDerOrNull(): ByteArray? = awesn1EncodeToDerOrNull()

@Deprecated("Use awesn1 APIs directly.")
fun <A : Asn1Element> Asn1Encodable<A>.encodeToTlvSafe(): KmmResult<A> = catching { encodeToTlv() }

@Deprecated("Use awesn1 APIs directly.")
fun Asn1Encodable<*>.encodeToDerSafe(): KmmResult<ByteArray> = catching { encodeToDer() }

@Deprecated(
    "Moved to at.asitplus.awesn1.decodeFromTlvOrNull().",
    ReplaceWith("at.asitplus.awesn1.decodeFromTlvOrNull(this, src, assertTag)")
)
fun <A : Asn1Element, T : Asn1Encodable<A>> Asn1Decodable<A, T>.decodeFromTlvOrNull(
    src: A,
    assertTag: at.asitplus.awesn1.Asn1Element.Tag? = null
): T? = awesn1DecodeFromTlvOrNull(src, assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeFromDer().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeFromDer(this, src, assertTag)")
)
fun <A : Asn1Element, T : Asn1Encodable<A>> Asn1Decodable<A, T>.decodeFromDer(
    src: ByteArray,
    assertTag: at.asitplus.awesn1.Asn1Element.Tag? = null
): T = awesn1DecodeFromDer(src, assertTag)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeFromDerOrNull().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeFromDerOrNull(this, src, assertTag)")
)
fun <A : Asn1Element, T : Asn1Encodable<A>> Asn1Decodable<A, T>.decodeFromDerOrNull(
    src: ByteArray,
    assertTag: at.asitplus.awesn1.Asn1Element.Tag? = null
): T? = awesn1DecodeFromDerOrNull(src, assertTag)

@Deprecated("Use awesn1 APIs directly.")
fun <A : Asn1Element, T : Asn1Encodable<A>> Asn1Decodable<A, T>.decodeFromTlvSafe(
    src: A,
    assertTag: at.asitplus.awesn1.Asn1Element.Tag? = null
): KmmResult<T> = catching { decodeFromTlv(src, assertTag) }

@Deprecated("Use awesn1 APIs directly.")
fun <A : Asn1Element, T : Asn1Encodable<A>> Asn1Decodable<A, T>.decodeFromDerSafe(
    src: ByteArray,
    assertTag: at.asitplus.awesn1.Asn1Element.Tag? = null
): KmmResult<T> = catching { decodeFromDer(src, assertTag) }

@Deprecated(
    "Moved to awesn1 PEM support.",
    ReplaceWith("at.asitplus.awesn1.Asn1PemEncodable")
)
interface PemEncodable<A : Asn1Element> : Asn1Encodable<A> {
    val canonicalPEMBoundary: String
}

private sealed interface PemDecoder<out T> {
    @JvmInline
    value class Real<out T>(val fn: (ByteArray) -> T) : PemDecoder<T>

    data object Default : PemDecoder<Nothing>

    companion object {
        inline operator fun <T> invoke(noinline fn: ((ByteArray) -> T)?) = when (fn) {
            null -> Default
            else -> Real(fn)
        }
    }
}

@Deprecated(
    "Moved to awesn1 PEM support.",
    ReplaceWith("at.asitplus.awesn1.Asn1PemDecodable")
)
abstract class PemDecodable<A : Asn1Element, out T : PemEncodable<A>>
private constructor(private val decoders: Map<String, PemDecoder<T>>) : Asn1Decodable<A, T> {

    constructor(vararg ebStrings: String) : this(ebStrings.associateWith { PemDecoder.Default })

    constructor(vararg decoders: Pair<String, ((ByteArray) -> T)?>) :
        this(decoders.associate { it.first to PemDecoder(it.second) })

    @Deprecated(
        "Moved to awesn1 PEM support.",
        ReplaceWith("at.asitplus.awesn1.decodeFromPem(src)")
    )
    fun decodeFromPem(src: String): KmmResult<T> = catching {
        val pemBlock = awesn1DecodeFromPem(src)
        val decoder = decoders[pemBlock.label]
            ?: throw IllegalArgumentException("Unknown encapsulation boundary string ${pemBlock.label}")
        when (decoder) {
            PemDecoder.Default -> decodeFromDer(pemBlock.payload)
            is PemDecoder.Real<T> -> decoder.fn(pemBlock.payload)
        }
    }
}

@Deprecated(
    "Moved to awesn1 PEM support.",
    ReplaceWith(
        "at.asitplus.awesn1.encodeToPem(at.asitplus.awesn1.PemBlock(label = canonicalPEMBoundary, payload = at.asitplus.awesn1.encoding.encodeToDer(this)))"
    )
)
fun PemEncodable<*>.encodeToPEM(): KmmResult<String> = catching {
    awesn1EncodeToPem(PemBlock(label = canonicalPEMBoundary, payload = encodeToDer()))
}
