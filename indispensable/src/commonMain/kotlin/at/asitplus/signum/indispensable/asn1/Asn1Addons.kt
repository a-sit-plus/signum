package at.asitplus.signum.indispensable.asn1

import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.encoding.*
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
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid


val UVARINT_MASK_BIGINT = BigInteger.fromUByte(UVARINT_MASK_UBYTE)

/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 */
@Throws(IllegalArgumentException::class)
fun BigInteger.toAsn1VarInt(): ByteArray = throughBuffer { it.writeAsn1VarInt(this) }

/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 *
 * @return the number of bytes written to the sink
 */
@Throws(IllegalArgumentException::class)
fun Sink.writeAsn1VarInt(number: BigInteger): Int {
    if(number==BigInteger.ZERO){ //fast case
        writeByte(0)
        return 1
    }
    require(!number.isNegative) { "Only non-negative numbers are supported" }
    val numBytes = (number.bitLength() + 6) / 7 // division rounding up
    (numBytes - 1).downTo(0).forEach { byteIndex ->
        writeByte(
            ((number shr (byteIndex * 7)).byteValue(exactRequired = false) and UVARINT_MASK) or
                    (if (byteIndex > 0) UVARINT_SINGLEBYTE_MAXVALUE else 0)
        )
    }
    //otherwise we won't ever write zero
    return  numBytes
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
        if (current < UVARINT_SINGLEBYTE_MAXVALUE_UBYTE) break
    }

    return result to accumulator.readByteArray()
}

/**
 * Decodes an unsigned BigInteger from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded unsigned BigInteger and the underlying varint-encoded bytes as `ByteArray`
 */
fun ByteArray.decodeAsn1VarBigInt(): Pair<BigInteger, ByteArray> = this.throughBuffer { it.decodeAsn1VarBigInt() }

/**
 * Converts this UUID to a BigInteger representation
 */
@OptIn(ExperimentalUuidApi::class)
fun Uuid.toBigInteger(): BigInteger = BigInteger.fromByteArray(toByteArray(), Sign.POSITIVE)

/**
 * Tries to convert a BigInteger to a UUID. Only guaranteed to work with BigIntegers that contain the unsigned (positive)
 * integer representation of a UUID, chances are high, though, that it works with random positive BigIntegers between
 * 16 and 14 bytes large.
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

/** Decode the [Asn1Primitive] as a [BigInteger]
 * @throws [Asn1Exception] on invalid input */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToBigInteger() =
    runRethrowing { decode(Asn1Element.Tag.INT) { BigInteger.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToBigInteger] */
inline fun Asn1Primitive.decodeToBigIntegerOrNull() = catching { decodeToBigInteger() }.getOrNull()

/**
 * Decodes a [BigInteger] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER
 */
@Throws(Asn1Exception::class)
fun BigInteger.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): BigInteger =
    runRethrowing { fromTwosComplementByteArray(bytes) }