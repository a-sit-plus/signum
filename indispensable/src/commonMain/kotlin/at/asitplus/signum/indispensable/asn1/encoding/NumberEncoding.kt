package at.asitplus.signum.indispensable.asn1.encoding

import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.ensureSize
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlinx.io.*
import kotlinx.io.bytestring.ByteString
import kotlin.experimental.or
import kotlin.math.ceil
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

internal val UVARINT_SINGLEBYTE_MAXVALUE_UBYTE: UByte = 0x80u
internal val UVARINT_SINGLEBYTE_MAXVALUE: Byte = 0x80.toByte()

internal val UVARINT_MASK = 0x7F
internal val UVARINT_MASK_UBYTE: UByte = 0x7Fu
internal val UVARINT_MASK_UINT: UInt = 0x7Fu
internal val UVARINT_MASK_ULONG: ULong = 0x7FuL
internal val UVARINT_MASK_BIGINT = BigInteger.fromUByte(UVARINT_MASK_UBYTE)

/**
 * Encode as a four-byte array
 */
fun Int.encodeTo4Bytes(): ByteArray = byteArrayOf(
    (this ushr 24).toByte(),
    (this ushr 16).toByte(),
    (this ushr 8).toByte(),
    (this).toByte()
)

/**
 * Encode as an eight-byte array
 */
fun Long.encodeTo8Bytes(): ByteArray = byteArrayOf(
    (this ushr 56).toByte(),
    (this ushr 48).toByte(),
    (this ushr 40).toByte(),
    (this ushr 32).toByte(),
    (this ushr 24).toByte(),
    (this ushr 16).toByte(),
    (this ushr 8).toByte(),
    (this).toByte()
)

/** Encodes an unsigned Long to a minimum-size twos-complement byte array */
fun ULong.toTwosComplementByteArray() = when {
    this >= 0x8000000000000000UL ->
        byteArrayOf(
            0x00,
            (this shr 56).toByte(),
            (this shr 48).toByte(),
            (this shr 40).toByte(),
            (this shr 32).toByte(),
            (this shr 24).toByte(),
            (this shr 16).toByte(),
            (this shr 8).toByte(),
            this.toByte()
        )

    else -> this.toLong().toTwosComplementByteArray()
}

/** Encodes an unsigned Int to a minimum-size twos-complement byte array */
fun UInt.toTwosComplementByteArray() = toLong().toTwosComplementByteArray()

/** Encodes a signed Long to a minimum-size twos-complement byte array */
fun Long.toTwosComplementByteArray() = when {
    (this >= -0x80L && this <= 0x7FL) ->
        byteArrayOf(
            this.toByte()
        )

    (this >= -0x8000L && this <= 0x7FFFL) ->
        byteArrayOf(
            (this ushr 8).toByte(),
            this.toByte()
        )

    (this >= -0x800000L && this <= 0x7FFFFFL) ->
        byteArrayOf(
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )

    (this >= -0x80000000L && this <= 0x7FFFFFFFL) ->
        byteArrayOf(
            (this ushr 24).toByte(),
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )

    (this >= -0x8000000000L && this <= 0x7FFFFFFFFFL) ->
        byteArrayOf(
            (this ushr 32).toByte(),
            (this ushr 24).toByte(),
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )

    (this >= -0x800000000000L && this <= 0x7FFFFFFFFFFFL) ->
        byteArrayOf(
            (this ushr 40).toByte(),
            (this ushr 32).toByte(),
            (this ushr 24).toByte(),
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )

    (this >= -0x80000000000000L && this <= 0x7FFFFFFFFFFFFFL) ->
        byteArrayOf(
            (this ushr 48).toByte(),
            (this ushr 40).toByte(),
            (this ushr 32).toByte(),
            (this ushr 24).toByte(),
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )

    else ->
        byteArrayOf(
            (this ushr 56).toByte(),
            (this ushr 48).toByte(),
            (this ushr 40).toByte(),
            (this ushr 32).toByte(),
            (this ushr 24).toByte(),
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )
}

/** Encodes a signed Int to a minimum-size twos-complement byte array */
fun Int.toTwosComplementByteArray() = toLong().toTwosComplementByteArray()

@Throws(IllegalArgumentException::class)
fun Int.Companion.fromTwosComplementByteArray(it: ByteArray) = when (it.size) {
    4 -> it[0].shiftLeftFirstInt(24) or
            (it[1] shiftLeftAsInt 16) or
            (it[2] shiftLeftAsInt 8) or
            (it[3] shiftLeftAsInt 0)

    3 -> it[0].shiftLeftFirstInt(16) or
            (it[1] shiftLeftAsInt 8) or
            (it[2] shiftLeftAsInt 0)

    2 -> it[0].shiftLeftFirstInt(8) or
            (it[1] shiftLeftAsInt 0)

    1 -> it[0].shiftLeftFirstInt(0)
    else -> throw IllegalArgumentException("Input with size $it is out of bounds for Int")
}

private infix fun Byte.shiftLeftAsInt(shift: Int) = this.toUByte().toInt() shl shift
private fun Byte.shiftLeftFirstInt(shift: Int) = toInt() shl shift

@Throws(IllegalArgumentException::class)
fun UInt.Companion.fromTwosComplementByteArray(it: ByteArray) =
    Long.fromTwosComplementByteArray(it).let {
        require((0 <= it) && (it <= 0xFFFFFFFFL)) { "Value $it is out of bounds for UInt" }
        it.toUInt()
    }

@Throws(IllegalArgumentException::class)
fun Long.Companion.fromTwosComplementByteArray(it: ByteArray) = when (it.size) {
    8 -> it[0].shiftLeftFirstLong(56) or
            (it[1] shiftLeftAsLong 48) or
            (it[2] shiftLeftAsLong 40) or
            (it[3] shiftLeftAsLong 32) or
            (it[4] shiftLeftAsLong 24) or
            (it[5] shiftLeftAsLong 16) or
            (it[6] shiftLeftAsLong 8) or
            (it[7] shiftLeftAsLong 0)

    7 -> it[0].shiftLeftFirstLong(48) or
            (it[1] shiftLeftAsLong 40) or
            (it[2] shiftLeftAsLong 32) or
            (it[3] shiftLeftAsLong 24) or
            (it[4] shiftLeftAsLong 16) or
            (it[5] shiftLeftAsLong 8) or
            (it[6] shiftLeftAsLong 0)

    6 -> it[0].shiftLeftFirstLong(40) or
            (it[1] shiftLeftAsLong 32) or
            (it[2] shiftLeftAsLong 24) or
            (it[3] shiftLeftAsLong 16) or
            (it[4] shiftLeftAsLong 8) or
            (it[5] shiftLeftAsLong 0)

    5 -> it[0].shiftLeftFirstLong(32) or
            (it[1] shiftLeftAsLong 24) or
            (it[2] shiftLeftAsLong 16) or
            (it[3] shiftLeftAsLong 8) or
            (it[4] shiftLeftAsLong 0)

    4 -> it[0].shiftLeftFirstLong(24) or
            (it[1] shiftLeftAsLong 16) or
            (it[2] shiftLeftAsLong 8) or
            (it[3] shiftLeftAsLong 0)

    3 -> it[0].shiftLeftFirstLong(16) or
            (it[1] shiftLeftAsLong 8) or
            (it[2] shiftLeftAsLong 0)

    2 -> it[0].shiftLeftFirstLong(8) or
            (it[1] shiftLeftAsLong 0)

    1 -> it[0].shiftLeftFirstLong(0)
    else -> throw IllegalArgumentException("Input with size $it is out of bounds for Long")
}

private infix fun Byte.shiftLeftAsLong(shift: Int) = this.toUByte().toLong() shl shift
private fun Byte.shiftLeftFirstLong(shift: Int) = toLong() shl shift

@Throws(IllegalArgumentException::class)
fun ULong.Companion.fromTwosComplementByteArray(it: ByteArray) = when {
    ((it.size == 9) && (it[0] == 0.toByte())) -> it.shiftLeftAsULong(1, 56) or
            it.shiftLeftAsULong(2, 48) or
            it.shiftLeftAsULong(3, 40) or
            it.shiftLeftAsULong(4, 32) or
            it.shiftLeftAsULong(5, 24) or
            it.shiftLeftAsULong(6, 16) or
            it.shiftLeftAsULong(7, 8) or
            it.shiftLeftAsULong(8, 0)

    else -> Long.fromTwosComplementByteArray(it).let {
        require(it >= 0) { "Value $it is out of bounds for ULong" }
        it.toULong()
    }
}

private fun ByteArray.shiftLeftAsULong(index: Int, shift: Int) = this[index].toUByte().toULong() shl shift

/** Encodes an unsigned Long to a minimum-size unsigned byte array */
fun Long.toUnsignedByteArray(): ByteArray {
    require(this >= 0)
    return this.toTwosComplementByteArray().let {
        if (it[0] == 0.toByte()) it.copyOfRange(1, it.size)
        else it
    }
}

/** Encodes an unsigned Int to a minimum-size unsigned byte array */
fun Int.toUnsignedByteArray() = toLong().toUnsignedByteArray()


/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 */
fun ULong.toAsn1VarInt(): ByteArray {
    if (this < UVARINT_SINGLEBYTE_MAXVALUE_UBYTE) return byteArrayOf(this.toByte()) //Fast case
    var offset = 0
    var result = mutableListOf<Byte>()

    var b0 = (this shr offset and UVARINT_MASK_ULONG).toByte()
    while ((this shr offset > 0uL) || offset == 0) {
        result += b0
        offset += 7
        if (offset > (ULong.SIZE_BITS - 1)) break //End of Fahnenstange
        b0 = (this shr offset and UVARINT_MASK_ULONG).toByte()
    }
    return with(result) {
        ByteArray(size) { fromBack(it) or asn1VarIntByteMask(it) }
    }
}

/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 */
@Throws(IllegalArgumentException::class)
fun BigInteger.toAsn1VarInt(): ByteArray {
    if (isZero()) return byteArrayOf(0)
    require(isPositive) { "Only positive Numbers are supported" }
    if (this < UVARINT_SINGLEBYTE_MAXVALUE_UBYTE) return byteArrayOf(this.byteValue(exactRequired = true)) //Fast case
    var offset = 0
    var result = mutableListOf<Byte>()

    val mask = BigInteger.fromUByte(UVARINT_MASK_UBYTE)
    var b0 = ((this shr offset) and mask).byteValue(exactRequired = false)
    while ((this shr offset > 0uL) || offset == 0) {
        result += b0
        offset += 7
        if (offset > (this.bitLength() - 1)) break //End of Fahnenstange
        b0 = ((this shr offset) and mask).byteValue(exactRequired = false)
    }

    return with(result) {
        ByteArray(size) { fromBack(it) or asn1VarIntByteMask(it) }
    }
}

/**
 * Encodes this number using unsigned VarInt encoding as used within ASN.1:
 * Groups of seven bits are encoded into a byte, while the highest bit indicates if more bytes are to come.
 *
 * This kind of encoding is used to encode [ObjectIdentifier] nodes and ASN.1 Tag values > 30
 */
fun UInt.toAsn1VarInt(): ByteArray {
    if (this < UVARINT_SINGLEBYTE_MAXVALUE_UBYTE) return byteArrayOf(this.toByte()) //Fast case
    var offset = 0
    var result = mutableListOf<Byte>()

    var b0 = (this shr offset and UVARINT_MASK_UINT).toByte()
    while ((this shr offset > 0u) || offset == 0) {
        result += b0
        offset += 7
        if (offset > (UInt.SIZE_BITS - 1)) break //End of Fahnenstange
        b0 = (this shr offset and 0x7Fu).toByte()
    }

    return with(result) {
        ByteArray(size) { fromBack(it) or asn1VarIntByteMask(it) }
    }
}

private fun MutableList<Byte>.asn1VarIntByteMask(it: Int) =
    (if (isLastIndex(it)) 0x00 else UVARINT_SINGLEBYTE_MAXVALUE).toByte()

private fun MutableList<Byte>.isLastIndex(it: Int) = it == size - 1

private fun MutableList<Byte>.fromBack(it: Int) = this[size - 1 - it]


/**
 * Decodes an ULong from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded ULong and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [ULong.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
inline fun Iterable<Byte>.decodeAsn1VarULong(): Pair<ULong, ByteArray> = iterator().decodeAsn1VarULong()

/**
 * Decodes an ULong from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded ULong and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [ULong.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
inline fun ByteArray.decodeAsn1VarULong(): Pair<ULong, ByteArray> = iterator().decodeAsn1VarULong()

/**
 * Decodes an ULong from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded ULong and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [ULong.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
fun Iterator<Byte>.decodeAsn1VarULong(): Pair<ULong, ByteArray> {
    var offset = 0
    var result = 0uL
    val accumulator = mutableListOf<Byte>()
    while (hasNext()) {
        val current = next().toUByte()
        accumulator += current.toByte()
        if (current >= 0x80.toUByte()) {
            result = (current and 0x7F.toUByte()).toULong() or (result shl 7)
        } else {
            result = (current and 0x7F.toUByte()).toULong() or (result shl 7)
            break
        }
        if (++offset > ceil(ULong.SIZE_BYTES.toFloat() * 8f / 7f)) throw IllegalArgumentException("Tag number too Large do decode into ULong!")
    }

    return result to accumulator.toByteArray()
}


/**
 * Decodes an unsigned BigInteger from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded unsigned BigInteger and the underlying varint-encoded bytes as `ByteArray`
 */
inline fun Iterable<Byte>.decodeAsn1VarBigInt(): Pair<BigInteger, ByteArray> = iterator().decodeAsn1VarBigInt()

/**
 * Decodes an unsigned BigInteger from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded unsigned BigInteger and the underlying varint-encoded bytes as `ByteArray`
 */
inline fun ByteArray.decodeAsn1VarBigInt(): Pair<BigInteger, ByteArray> = iterator().decodeAsn1VarBigInt()


/**
 * Decodes a BigInteger from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded BigInteger and the underlying varint-encoded bytes as `ByteArray`
 */
fun Iterator<Byte>.decodeAsn1VarBigInt(): Pair<BigInteger, ByteArray> {
    var result = BigInteger.ZERO
    val mask = BigInteger.fromUByte(0x7Fu)
    val accumulator = mutableListOf<Byte>()
    while (hasNext()) {
        val curByte = next()
        val current = BigInteger(curByte.toUByte().toInt())
        accumulator += curByte
        result = (current and mask) or (result shl 7)
        if (current < 0x80.toUByte()) break
    }

    return result to accumulator.toByteArray()
}


//TOOD: how to not duplicate all this???
/**
 * Decodes an UInt from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded UInt and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [UInt.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
inline fun Iterable<Byte>.decodeAsn1VarUInt(): Pair<UInt, ByteArray> = iterator().decodeAsn1VarUInt()

/**
 * Decodes an UInt from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded UInt and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [UInt.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
inline fun ByteArray.decodeAsn1VarUInt(): Pair<UInt, ByteArray> = iterator().decodeAsn1VarUInt()

/**
 * Decodes an UInt from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded UInt and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [UInt.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
fun Iterator<Byte>.decodeAsn1VarUInt(): Pair<UInt, ByteArray> {
    var offset = 0
    var result = 0u
    val accumulator = mutableListOf<Byte>()
    while (hasNext()) {
        val current = next().toUByte()
        accumulator += current.toByte()
        if (current >= 0x80.toUByte()) {
            result = (current and 0x7F.toUByte()).toUInt() or (result shl 7)
        } else {
            result = (current and 0x7F.toUByte()).toUInt() or (result shl 7)
            break
        }
        if (++offset > ceil(UInt.SIZE_BYTES.toFloat() * 8f / 7f)) throw IllegalArgumentException("Tag number too Large do decode into UInt!")
    }

    return result to accumulator.toByteArray()
}

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
    catching { fromByteArray(bigInteger.toByteArray().ensureSize(16)) }.getOrNull()


///////////KTX-IO

/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 *
 * @return the number of bytes written to the sink
 */
fun Sink.writeAsn1VarInt(number: ULong) = writeAsn1VarInt(number, ULong.SIZE_BITS)

/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 *
 * @return the number of bytes written to the sink
 */
fun Sink.writeAsn1VarInt(number: UInt) = writeAsn1VarInt(number.toULong(), UInt.SIZE_BITS)

/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 *
 * @return the number of bytes written to the sink
 */
private fun Sink.writeAsn1VarInt(number: ULong, bits: Int):Int {
    if (number < 128u) return writeByte(number.toByte()).run { 1 } //Fast case
    var offset = 0
    var result = mutableListOf<Byte>()

    var b0 = (number shr offset and UVARINT_MASK_ULONG).toByte()
    while ((number shr offset > 0uL) || offset == 0) {
        result += b0
        offset += 7
        if (offset > (bits - 1)) break //End of Fahnenstange
        b0 = (number shr offset and UVARINT_MASK_ULONG).toByte()
    }
    result.forEachIndexed { index, _ ->
        writeByte(result.fromBack(index) or result.asn1VarIntByteMask(index))
    }
    return result.size
}

/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 *
 * @return the number of bytes written to the sink
 */
@Throws(IllegalArgumentException::class)
fun Sink.writeAsn1VarInt(number: BigInteger): Int {
    if (number.isZero()) return writeByte(0).run { 1 }
    require(number.isPositive) { "Only positive Numbers are supported" }
    if (number < UVARINT_SINGLEBYTE_MAXVALUE) return writeByte(number.byteValue(exactRequired = true)).run { 1 } //Fast case
    var offset = 0
    var result = mutableListOf<Byte>()


    var b0 = ((number shr offset) and UVARINT_MASK_BIGINT).byteValue(exactRequired = false)
    while ((number shr offset > 0u) || offset == 0) {
        result += b0
        offset += 7
        if (offset > (number.bitLength() - 1)) break //End of Fahnenstange
        b0 = ((number shr offset) and UVARINT_MASK_BIGINT).byteValue(exactRequired = false)
    }
    result.forEachIndexed { index, _ ->
        writeByte(result.fromBack(index) or result.asn1VarIntByteMask(index))
    }
    return result.size
}

/**
 * Decodes an ASN.1 unsigned varint to an [ULong], copying all bytes from the source into a [ByteArray].
 *
 * @return the decoded [ULong] and the underlying varint-encoded bytes as ByteString
 * @throws IllegalArgumentException if the number is larger than [ULong.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
fun Source.decodeAsn1VarULong(): Pair<ULong, ByteArray> = decodeAsn1VarULong(ULong.SIZE_BITS)



/**
 * Decodes an ASN.1 unsigned varint to an [UInt], copying all bytes from the source into a [ByteArray].
 *
 * @return the decoded [UInt] and the underlying varint-encoded bytes as ByteString
 * @throws IllegalArgumentException if the number is larger than [UInt.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
fun Source.decodeAsn1VarUInt(): Pair<UInt, ByteArray> =
    decodeAsn1VarULong(Int.SIZE_BITS).let { (num, bytes) -> num.toUInt() to bytes }

/**
 * Decodes an ASN.1 unsigned varint to an ULong allocating at most [bits] many bits .
 * This function is useful as an intermediate processing step, since it also returns a [ByteArray]
 * holding all bytes consumed from the source.
 * This operation essentially moves bytes around without copying.
 *
 * @return the decoded ASN.1 varint as an [ULong] and the underlying varint-encoded bytes as [ByteArray]
 * @throws IllegalArgumentException if the resulting number requires more than [bits] many bits to be represented
 */
@Throws(IllegalArgumentException::class)
//TODO: find a way to do this without allocating an ULong when using UInt
private fun Source.decodeAsn1VarULong(bits: Int): Pair<ULong, ByteArray> {
    var offset = 0
    var result = 0uL
    val accumulator = Buffer()
    while (!exhausted()) {
        val current = readUByte()
        accumulator.writeUByte(current)
        if (current >= UVARINT_SINGLEBYTE_MAXVALUE_UBYTE) {
            result = (current and UVARINT_MASK_UBYTE).toULong() or (result shl 7)
        } else {
            result = (current and UVARINT_MASK_UBYTE).toULong() or (result shl 7)
            break
        }
        if (++offset > ceil((bits * 8).toFloat() * 8f / 7f)) throw IllegalArgumentException("Tag number too Large do decode into $bits bits!")
    }

    return result to accumulator.readByteArray()
}

/**
 * Decodes a BigInteger from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * This function is useful as an intermediate processing step, since it also returns a [ByteArray]
 * holding all bytes consumed from the source.
 * This operation essentially moves bytes around without copying.
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
 * Writes a signed long using twos-complement encoding using the fewest bytes required
 * Allows for omitting the leading zero byte. This can be useful in certain number encodings such as
 * in ASN.1 tag length encoding.
 *
 * @return the number of byte written to the sink
 * */
fun Sink.writeTwosComplementLong(number: Long, padded: Boolean = true): Int = when {
    (number >= -0x80L && number <= 0x7FL) -> {
        writeByte(number.toByte())
        1
    }

    (number >= -0x8000L && number <= 0x7FFFL) -> {
        val byteWritten = writeOrSkipPadding(number, 8, padded)
        writeByte(number.toByte())
        1 + byteWritten
    }

    (number >= -0x800000L && number <= 0x7FFFFFL) -> {
        val byteWritten = writeOrSkipPadding(number, 16, padded)
        writeByte((number ushr 8).toByte())
        writeByte(number.toByte())
        2 + byteWritten
    }

    (number >= -0x80000000L && number <= 0x7FFFFFFFL) -> {
        val byteWritten = writeOrSkipPadding(number, 24, padded)
        writeByte((number ushr 16).toByte())
        writeByte((number ushr 8).toByte())
        writeByte(number.toByte())
        3 + byteWritten
    }

    (number >= -0x8000000000L && number <= 0x7FFFFFFFFFL) -> {
        val byteWritten = writeOrSkipPadding(number, 32, padded)
        writeByte((number ushr 24).toByte())
        writeByte((number ushr 16).toByte())
        writeByte((number ushr 8).toByte())
        writeByte(number.toByte())
        4 + byteWritten
    }

    (number >= -0x800000000000L && number <= 0x7FFFFFFFFFFFL) -> {
        val byteWritten = writeOrSkipPadding(number, 40, padded)
        writeByte((number ushr 32).toByte())
        writeByte((number ushr 24).toByte())
        writeByte((number ushr 16).toByte())
        writeByte((number ushr 8).toByte())
        writeByte(number.toByte())
        5 + byteWritten
    }

    (number >= -0x80000000000000L && number <= 0x7FFFFFFFFFFFFFL) -> {
        val byteWritten = writeOrSkipPadding(number, 48, padded)
        writeByte((number ushr 40).toByte())
        writeByte((number ushr 32).toByte())
        writeByte((number ushr 24).toByte())
        writeByte((number ushr 16).toByte())
        writeByte((number ushr 8).toByte())
        writeByte(number.toByte())
        6 + byteWritten
    }

    else -> {
        val byteWritten = writeOrSkipPadding(number, 56, padded)
        writeByte((number ushr 48).toByte())
        writeByte((number ushr 40).toByte())
        writeByte((number ushr 32).toByte())
        writeByte((number ushr 24).toByte())
        writeByte((number ushr 16).toByte())
        writeByte((number ushr 8).toByte())
        writeByte(number.toByte())
        7 + byteWritten
    }

}

private inline fun Sink.writeOrSkipPadding(number: Long, shift: Int, padded: Boolean): Int {
    val byte = (number ushr shift).toByte()
    val writeFirstByte = padded || (byte != 0.toByte())
    if (writeFirstByte) writeByte(byte)
    return if (writeFirstByte) 1 else 0
}

/**
 *  Encodes an unsigned Long to a minimum-size twos-complement byte array
 * @return the number of bytes written
 */
fun Sink.writeTwosComplement(number: ULong): Int = when {
    number >= 0x8000000000000000UL -> {
        writeByte(0x00)
        writeByte((number shr 56).toByte())
        writeByte((number shr 48).toByte())
        writeByte((number shr 40).toByte())
        writeByte((number shr 32).toByte())
        writeByte((number shr 24).toByte())
        writeByte((number shr 16).toByte())
        writeByte((number shr 8).toByte())
        writeByte(number.toByte())
        9
    }

    else -> writeTwosComplementLong(number.toLong())
}


/** Encodes an unsigned Int to a minimum-size twos-complement byte array
 * @return the number of bytes written to the sink
 */
fun Sink.writeTwosComplementUInt(number: UInt) = writeTwosComplementLong(number.toLong())

/**
 * Consumes data from this source and interprets it as a signed [ULong].
 * Tries to read exactly [nBytes] many bytes from this source, or all remaining data if not set.
 *
 * @throws IllegalArgumentException if too much or too little data is present
 */
@Throws(IllegalArgumentException::class)
fun Source.readTwosComplementULong(nBytes: Int? = null): ULong {
    if(nBytes==0) return 0uL
    require(!exhausted()) { "Source is exhausted" }
    val firstByte = readByte()
    var result = firstByte.toUByte().toULong()
    var bytesRead = 1
    while (nBytes?.let { bytesRead < nBytes } ?: !exhausted()) {
        require(bytesRead ++ <= 8) { "Input too large" }
        result = (result shl 8) or readUByte().toULong()
    }
    return result
}


/**
 * Consumes data from this source and interprets it as a [Long].
 * Tries to read exactly [nBytes] many bytes from this source, or all remaining data if not set.
 *
 * @throws IllegalArgumentException if too much or too little data is present
 */
fun Source.readTwosComplementLong(nBytes: Int? = null): Long {
    if (nBytes == 0) return 0L
    require(!exhausted()) { "Source is exhausted" }
    val firstByte = readByte()
    var result = 0L
    var offset = 48 //one less than max shift (56), since first byte is read
    var bytesRead = 1
    while (nBytes?.let { bytesRead < nBytes } ?: !exhausted()) {
        require(offset >= 0) { "Input too large" }
        result = result or readByte().shiftLeftAsLong(offset)
        bytesRead++
        offset -= 8
    }
    return result.shr(offset + 8) or firstByte.shiftLeftFirstLong(48 - offset)
}


/**
 * Consumes data from this source and interprets it as a signed [Int]
 * Tries to read exactly [nBytes] many bytes from this source, or all remaining data if not set.
 *
 * @throws IllegalArgumentException if too much or too little data is present
 */
@Throws(IllegalArgumentException::class)
fun Source.readTwosComplementInt(nBytes: Int? = null): Int {
    if (nBytes == 0) return 0
    require(!exhausted()) { "Source is exhausted" }
    val firstByte = readByte()
    var bytesRead = 1
    var result = 0
    var offset = 16 //one less than max shift (24), since first byte is read
    while (nBytes?.let { bytesRead < nBytes } ?: !exhausted()) {
        require(offset >= 0) { "Input too large" }
        result = result or readByte().shiftLeftAsInt(offset)
        bytesRead++
        offset -= 8
    }
    return result.shr(offset + 8) or firstByte.shiftLeftFirstInt(16 - offset)
}

/**
 * Consumes all remaining data from this source and interprets it as a [UInt]
 *
 * @throws IllegalArgumentException if no or too much data is present
 */
@Throws(IllegalArgumentException::class)
fun Source.readTwosComplementUInt() =
    readTwosComplementLong().let {
        require((0 <= it) && (it <= 0xFFFFFFFFL)) { "Value $it is out of bounds for UInt" }
        it.toUInt()
    }

/**
 *  Encodes a positive Long to a minimum-size unsigned byte array, omitting the leading zero
 *
 *  @throws IllegalArgumentException if [number] is negative
 *  @return the number of bytes written
 */
fun Sink.writeUnsignedTwosComplementLong(number: Long): Int {
    require(number >= 0)
    return writeTwosComplementLong(number, padded = false)
}