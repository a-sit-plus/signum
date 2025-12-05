package at.asitplus.signum.indispensable.asn1.encoding

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.VarUInt.Companion.decodeAsn1VarBigUInt
import at.asitplus.signum.indispensable.asn1.VarUInt.Companion.writeAsn1VarInt
import kotlinx.io.*
import kotlin.math.ceil

private const val UVARINT_SINGLEBYTE_MAXVALUE_UBYTE: UByte = 0x80u
internal const val UVARINT_SINGLEBYTE_MAXVALUE: Byte = 0x80.toByte()
internal const val UVARINT_MASK_UBYTE: UByte = 0x7Fu

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

fun UInt.Companion.fromTwosComplementByteArray(it: ByteArray) =
    Long.fromTwosComplementByteArray(it).let {
        require((0 <= it) && (it <= 0xFFFFFFFFL)) { "Value $it is out of bounds for UInt" }
        it.toUInt()
    }

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
fun Long.toUnsignedByteArray(): ByteArray = throughBuffer { it.writeMagnitudeLong(this) }

/** Encodes an unsigned Int to a minimum-size unsigned byte array */
fun Int.toUnsignedByteArray() = toLong().toUnsignedByteArray()


/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 */
fun ULong.toAsn1VarInt(): ByteArray = throughBuffer { it.writeAsn1VarInt(this) }

/**
 * Encodes this number using unsigned VarInt encoding as used within ASN.1:
 * Groups of seven bits are encoded into a byte, while the highest bit indicates if more bytes are to come.
 *
 * This kind of encoding is used to encode [ObjectIdentifier] nodes and ASN.1 Tag values > 30
 */
fun UInt.toAsn1VarInt(): ByteArray = throughBuffer { it.writeAsn1VarInt(this) }

private fun List<Byte>.asn1VarIntByteMask(it: Int) =
    (if (isLastIndex(it)) 0x00 else UVARINT_SINGLEBYTE_MAXVALUE)

private fun List<Byte>.isLastIndex(it: Int) = it == size - 1

private fun List<Byte>.fromBack(it: Int) = this[size - 1 - it]


/**
 * Decodes an ULong from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded ULong and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [ULong.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
fun ByteArray.decodeAsn1VarULong(): Pair<ULong, ByteArray> = this.throughBuffer { it.decodeAsn1VarULong() }

/**
 * Decodes an UInt from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded UInt and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [UInt.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
fun ByteArray.decodeAsn1VarUInt(): Pair<UInt, ByteArray> = this.throughBuffer { it.decodeAsn1VarUInt() }


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
private fun Sink.writeAsn1VarInt(number: ULong, bits: Int): Int {
    if (number == 0uL) { //fast case
        writeByte(0)
        return 1
    }
    val numBytes = (number.bitLength + 6) / 7 // division rounding up
    (numBytes - 1).downTo(0).forEach { byteIndex ->
        writeUByte(
            ((number shr (byteIndex * 7)).toUByte() and UVARINT_MASK_UBYTE) or
                    (if (byteIndex > 0) UVARINT_SINGLEBYTE_MAXVALUE_UBYTE else 0u)
        )
    }
    return numBytes
}

/** the number of bits required to represent this number */
val ULong.bitLength inline get() = ULong.SIZE_BITS - this.countLeadingZeroBits()

/** the number of bits required to represent this number */
val Long.bitLength inline get() = Long.SIZE_BITS - this.countLeadingZeroBits()

/** the number of bits required to represent this number */
val UInt.bitLength inline get() = UInt.SIZE_BITS - this.countLeadingZeroBits()

/** the number of bits required to represent this number */
val UByte.bitLength inline get() = UByte.SIZE_BITS - this.countLeadingZeroBits()

/** the number of bits required to represent this number */
val Int.bitLength inline get() = Int.SIZE_BITS - this.countLeadingZeroBits()

/**
 * Decodes an ASN.1 unsigned varint to an [ULong], copying all bytes from the source into a [ByteArray].
 *
 * @return the decoded [ULong] and the underlying varint-encoded bytes as [ByteArray]
 * @throws IllegalArgumentException if the number is larger than [ULong.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
fun Source.decodeAsn1VarULong(): Pair<ULong, ByteArray> = decodeAsn1VarInt(ULong.SIZE_BITS)

/**
 * Decodes an ASN.1 unsigned varint to an [UInt], copying all bytes from the source into a [ByteArray].
 *
 * @return the decoded [UInt] and the underlying varint-encoded bytes as [ByteArray]
 * @throws IllegalArgumentException if the number is larger than [UInt.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
fun Source.decodeAsn1VarUInt(): Pair<UInt, ByteArray> =
    decodeAsn1VarInt(UInt.SIZE_BITS).let { (n, b) -> n.toUInt() to b }

/**
 * Decodes an ASN.1 unsigned varint to an ULong allocating at most [bits] many bits .
 * This function is useful as an intermediate processing step, since it also returns a [Buffer]
 * holding all bytes consumed from the source.
 * This operation essentially moves bytes around without copying.
 *
 * @return the decoded ASN.1 varint as an [ULong] and the underlying varint-encoded bytes as [Buffer]
 * @throws IllegalArgumentException if the resulting number requires more than [bits] many bits to be represented
 */
@Throws(IllegalArgumentException::class)
private fun Source.decodeAsn1VarInt(bits: Int): Pair<ULong, ByteArray> {
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
        if (++offset > ceil((bits * 8).toFloat() * 8f / 7f)) throw IllegalArgumentException("Number too Large do decode into $bits bits!")
    }

    return result to accumulator.readByteArray()
}

/**
 * Writes a signed long using twos-complement encoding using the fewest bytes required
 *
 * @return the number of byte written to the sink
 */
fun Sink.writeTwosComplementLong(number: Long): Int = appendUnsafe(number.toTwosComplementByteArray())

/**
 * Encodes an unsigned Long to a minimum-size twos-complement byte array
 * @return the number of bytes written
 */
fun Sink.writeTwosComplementULong(number: ULong): Int = appendUnsafe(number.toTwosComplementByteArray())


/** Encodes an unsigned Int to a minimum-size twos-complement byte array
 * @return the number of bytes written to the sink
 */
fun Sink.writeTwosComplementUInt(number: UInt) = writeTwosComplementLong(number.toLong())

/**
 * Consumes exactly [nBytes] from this source and interprets it as a signed [ULong].
 *
 * @throws IllegalArgumentException if too much or too little data is present
 */
@Throws(IllegalArgumentException::class)
fun Source.readTwosComplementULong(nBytes: Int): ULong = ULong.fromTwosComplementByteArray(readByteArray(nBytes))


/**
 * Consumes exactly [nBytes] from this source and interprets it as a [Long].
 *
 * @throws IllegalArgumentException if too much or too little data is present
 */
@Throws(IllegalArgumentException::class)
fun Source.readTwosComplementLong(nBytes: Int): Long = Long.fromTwosComplementByteArray(readByteArray(nBytes))


/**
 * Consumes exactly [nBytes] from this source and interprets it as a signed [Int]
 *
 * @throws IllegalArgumentException if too much or too little data is present
 */
@Throws(IllegalArgumentException::class)
fun Source.readTwosComplementInt(nBytes: Int): Int = Int.fromTwosComplementByteArray(readByteArray(nBytes))

/**
 * Consumes exactly [nBytes] remaining data from this source and interprets it as a [UInt]
 *
 * @throws IllegalArgumentException if no or too much data is present
 */
@Throws(IllegalArgumentException::class)
fun Source.readTwosComplementUInt(nBytes: Int): UInt = UInt.fromTwosComplementByteArray(readByteArray(nBytes))

/**
 *  Encodes a positive Long to a minimum-size unsigned byte array, omitting the leading zero
 *
 *  @throws IllegalArgumentException if [number] is negative
 *  @return the number of bytes written
 */
fun Sink.writeMagnitudeLong(number: Long): Int {
    require(number >= 0)
    return number.toTwosComplementByteArray().let { appendUnsafe(it, if (it[0] == 0.toByte()) 1 else 0) }
}

/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 */
@Throws(IllegalArgumentException::class)
fun Asn1Integer.toAsn1VarInt(): ByteArray = throughBuffer { it.writeAsn1VarInt(this) }

/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 *
 * @return the number of bytes written to the sink
 */
@Throws(IllegalArgumentException::class)
fun Sink.writeAsn1VarInt(number: Asn1Integer): Int {
    require(number is Asn1Integer.Positive) { "Only non-negative numbers are supported" }
    return writeAsn1VarInt(number.uint)
}

/**
 * Decodes an ASN.1 unsigned varint to a [Asn1Integer], copying all bytes from the source into a [ByteArray].
 *
 * @return the decoded [Asn1Integer] and the underlying varint-encoded bytes as [ByteArray]
 */
fun Source.decodeAsn1VarBigInt(): Pair<Asn1Integer, ByteArray> =
    decodeAsn1VarBigUInt().let { (uint, bytes) -> Asn1Integer.Positive(uint) to bytes }

/**
 * Decodes an unsigned [Asn1Integer] from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded unsigned BigInteger and the underlying varint-encoded bytes as `ByteArray`
 */
fun ByteArray.decodeAsn1VarBigInt(): Pair<Asn1Integer, ByteArray> = this.throughBuffer { it.decodeAsn1VarBigInt() }