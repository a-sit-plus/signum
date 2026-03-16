package at.asitplus.signum.indispensable.asn1

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.awesn1.Asn1Decodable
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1PemDecodable
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.decode
import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.encodeToAsn1ContentBytes
import at.asitplus.signum.internals.ensureSize
import com.ionspin.kotlin.bignum.decimal.BigDecimal
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.integer.util.fromTwosComplementByteArray
import com.ionspin.kotlin.bignum.integer.util.toTwosComplementByteArray
import kotlinx.io.Buffer
import kotlinx.io.Sink
import kotlinx.io.Source
import kotlinx.io.readByteArray
import kotlin.experimental.and
import kotlin.experimental.or
import kotlin.jvm.JvmInline
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

private fun Asn1Integer.Sign.toBigIntegerSign() = when (this) {
    Asn1Integer.Sign.POSITIVE -> Sign.POSITIVE
    Asn1Integer.Sign.NEGATIVE -> Sign.NEGATIVE
}

private fun Sign.toAsn1IntegerSign() = when (this) {
    Sign.ZERO, Sign.POSITIVE -> Asn1Integer.Sign.POSITIVE
    Sign.NEGATIVE -> Asn1Integer.Sign.NEGATIVE
}

/** Converts the [Asn1Integer] to the corresponding [BigInteger]. */
fun Asn1Integer.toBigInteger(): BigInteger =
    BigInteger.fromByteArray(this.magnitude, this.sign.toBigIntegerSign())

/** Converts the [BigInteger] to the corresponding [Asn1Integer]. */
fun BigInteger.toAsn1Integer(): Asn1Integer =
    Asn1Integer.fromByteArray(this.toByteArray(), this.getSign().toAsn1IntegerSign())

private val UVARINT_MASK_BIGINT = BigInteger.fromUByte(0x7Fu)

/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 */
@Throws(IllegalArgumentException::class)
fun BigInteger.toAsn1VarInt(): ByteArray = Buffer().also { it.writeAsn1VarInt(this) }.readByteArray()

/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 *
 * @return the number of bytes written to the sink
 */
@Throws(IllegalArgumentException::class)
fun Sink.writeAsn1VarInt(number: BigInteger): Int {
    if (number == BigInteger.ZERO) { //fast case
        writeByte(0)
        return 1
    }
    require(!number.isNegative) { "Only non-negative numbers are supported" }
    val numBytes = (number.bitLength() + 6) / 7 // division rounding up
    (numBytes - 1).downTo(0).forEach { byteIndex ->
        writeByte(
            ((number shr (byteIndex * 7)).byteValue(exactRequired = false) and 0x7F) or
                    (if (byteIndex > 0) 0x80.toByte() else 0)
        )
    }
    return numBytes
}


/**
 * Decodes an ASN.1 unsigned varint to a [BigInteger], copying all bytes from the source into a [ByteArray].
 *
 * @return the decoded [BigInteger] and the underlying varint-encoded bytes as [ByteArray]
 */
fun Source.decodeAsn1VarBigInt(): Pair<BigInteger, ByteArray> {
    var result = BigInteger.ZERO
    val accumulator = Buffer()
    while (!exhausted()) {
        val curByte = readByte()
        val current = BigInteger(curByte.toUByte().toInt())
        accumulator.writeByte(curByte)
        result = (current and UVARINT_MASK_BIGINT) or (result shl 7)
        if (current < 0x80u) break
    }

    return result to accumulator.readByteArray()
}

/**
 * Decodes an unsigned BigInteger from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded unsigned BigInteger and the underlying varint-encoded bytes as `ByteArray`
 */
fun ByteArray.decodeAsn1VarBigInt(): Pair<BigInteger, ByteArray> = Buffer().apply { write(this@decodeAsn1VarBigInt) }.decodeAsn1VarBigInt()

/**
 * Converts this UUID to a BigInteger representation
 */
@OptIn(ExperimentalUuidApi::class)
fun Uuid.toBigInteger(): BigInteger = BigInteger.fromByteArray(toByteArray(), Sign.POSITIVE)

/**
 * Tries to convert a BigInteger to a UUID. Only guaranteed to work with BigIntegers that contain the unsigned (positive)
 * integer representation of a UUID, chances are high, though, that it works with random positive BigIntegers between
 * 16 and 14 bytes long.
 *
 * Returns `null` if conversion fails. Never throws.
 */
@OptIn(ExperimentalUuidApi::class)
fun Uuid.Companion.fromBigintOrNull(bigInteger: BigInteger): Uuid? =
    catchingUnwrapped { fromByteArray(bigInteger.toByteArray().ensureSize(16)) }.getOrNull()

/** Creates an INTEGER [Asn1Primitive] from [value] */
fun Asn1.Int(value: BigInteger) = value.encodeToAsn1Primitive()


/** Produces an INTEGER as [Asn1Primitive] */
fun BigInteger.encodeToAsn1Primitive() = Asn1Primitive(Asn1Element.Tag.INT, encodeToAsn1ContentBytes())


/** Encodes this number into a [ByteArray] using the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER */
fun BigInteger.encodeToAsn1ContentBytes() = toTwosComplementByteArray()

/**
 * Decode the [Asn1Primitive] as a [BigInteger]. [assertTag] defaults to [Asn1Element.Tag.INT], but can be
 * overridden (for implicitly tagged integers, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToBigInteger(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    runRethrowing { decode(assertTag) { BigInteger.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToBigInteger] */
@Suppress("NOTHING_TO_INLINE")
inline fun Asn1Primitive.decodeToBigIntegerOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    catchingUnwrapped { decodeToBigInteger(assertTag) }.getOrNull()

/**
 * Decodes a [BigInteger] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER
 */
@Throws(Asn1Exception::class)
fun BigInteger.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): BigInteger =
    runRethrowing { fromTwosComplementByteArray(bytes) }

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

abstract class LabelPemDecodable<A : Asn1Element, out T : Asn1Encodable<A>>
private constructor(private val decoders: Map<String, PemDecoder<T>>) : Asn1PemDecodable<A, T> {

    constructor(vararg labels: String) : this(labels.associateWith { PemDecoder.Default })

    constructor(vararg decoders: Pair<String, ((ByteArray) -> T)?>) :
        this(decoders.associate { it.first to PemDecoder(it.second) })

    override fun decodeFromPem(src: PemBlock): T {
        val decoder = decoders[src.label]
            ?: throw IllegalArgumentException("Unknown encapsulation boundary string ${src.label}")
        return when (decoder) {
            PemDecoder.Default -> decodeFromDer(src.payload)
            is PemDecoder.Real<T> -> decoder.fn(src.payload)
        }
    }

    fun decodeFromPem(src: String): KmmResult<T> = catching {
        val pemBlock: PemBlock = at.asitplus.awesn1.decodeFromPem(src)
        this@LabelPemDecodable.decodeFromPem(pemBlock)
    }
}

internal val DEFAULT_PEM_DECODER: ((ByteArray)->Nothing)? = null
