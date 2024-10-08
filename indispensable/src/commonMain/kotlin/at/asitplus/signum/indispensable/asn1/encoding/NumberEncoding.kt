package at.asitplus.signum.indispensable.asn1.encoding

import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import kotlin.experimental.or
import kotlin.math.ceil


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
    4 -> (it[0].toInt() shl 24) or (it[1].toUByte().toInt() shl 16) or (it[2].toUByte()
        .toInt() shl 8) or (it[3].toUByte().toInt())

    3 -> (it[0].toInt() shl 16) or (it[1].toUByte().toInt() shl 8) or (it[2].toUByte().toInt())
    2 -> (it[0].toInt() shl 8) or (it[1].toUByte().toInt() shl 0)
    1 -> (it[0].toInt())
    else -> throw IllegalArgumentException("Input with size $it is out of bounds for Int")
}

fun UInt.Companion.fromTwosComplementByteArray(it: ByteArray) =
    Long.fromTwosComplementByteArray(it).let {
        require((0 <= it) && (it <= 0xFFFFFFFFL)) { "Value $it is out of bounds for UInt" }
        it.toUInt()
    }

fun Long.Companion.fromTwosComplementByteArray(it: ByteArray) = when (it.size) {
    8 -> (it[0].toLong() shl 56) or (it[1].toUByte().toLong() shl 48) or (it[2].toUByte().toLong() shl 40) or
            (it[3].toUByte().toLong() shl 32) or (it[4].toUByte().toLong() shl 24) or
            (it[5].toUByte().toLong() shl 16) or (it[6].toUByte().toLong() shl 8) or (it[7].toUByte().toLong())

    7 -> (it[0].toLong() shl 48) or (it[1].toUByte().toLong() shl 40) or (it[2].toUByte().toLong() shl 32) or
            (it[3].toUByte().toLong() shl 24) or (it[4].toUByte().toLong() shl 16) or
            (it[5].toUByte().toLong() shl 8) or (it[6].toUByte().toLong())

    6 -> (it[0].toLong() shl 40) or (it[1].toUByte().toLong() shl 32) or (it[2].toUByte().toLong() shl 24) or
            (it[3].toUByte().toLong() shl 16) or (it[4].toUByte().toLong() shl 8) or (it[5].toUByte().toLong())

    5 -> (it[0].toLong() shl 32) or (it[1].toUByte().toLong() shl 24) or (it[2].toUByte().toLong() shl 16) or
            (it[3].toUByte().toLong() shl 8) or (it[4].toUByte().toLong())

    4 -> (it[0].toLong() shl 24) or (it[1].toUByte().toLong() shl 16) or (it[2].toUByte().toLong() shl 8) or
            (it[3].toUByte().toLong())

    3 -> (it[0].toLong() shl 16) or (it[1].toUByte().toLong() shl 8) or (it[2].toUByte().toLong())
    2 -> (it[0].toLong() shl 8) or (it[1].toUByte().toLong() shl 0)
    1 -> (it[0].toLong())
    else -> throw IllegalArgumentException("Input with size $it is out of bounds for Long")
}

fun ULong.Companion.fromTwosComplementByteArray(it: ByteArray) = when {
    ((it.size == 9) && (it[0] == 0.toByte())) ->
        (it[1].toUByte().toULong() shl 56) or (it[2].toUByte().toULong() shl 48) or (it[3].toUByte()
            .toULong() shl 40) or
                (it[4].toUByte().toULong() shl 32) or (it[5].toUByte().toULong() shl 24) or
                (it[6].toUByte().toULong() shl 16) or (it[7].toUByte().toULong() shl 8) or
                (it[8].toUByte().toULong())

    else -> Long.fromTwosComplementByteArray(it).let {
        require(it >= 0) { "Value $it is out of bounds for ULong" }
        it.toULong()
    }
}

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
    if (this < 128u) return byteArrayOf(this.toByte()) //Fast case
    var offset = 0
    var result = mutableListOf<Byte>()

    var b0 = (this shr offset and 0x7FuL).toByte()
    while ((this shr offset > 0uL) || offset == 0) {
        result += b0
        offset += 7
        if (offset > (ULong.SIZE_BITS - 1)) break //End of Fahnenstange
        b0 = (this shr offset and 0x7FuL).toByte()
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
    if (this < 128u) return byteArrayOf(this.toByte()) //Fast case
    var offset = 0
    var result = mutableListOf<Byte>()

    var b0 = (this shr offset and 0x7Fu).toByte()
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

private fun MutableList<Byte>.asn1VarIntByteMask(it: Int) = (if (isLastIndex(it)) 0x00 else 0x80).toByte()

private fun MutableList<Byte>.isLastIndex(it: Int) = it == size - 1

private fun MutableList<Byte>.fromBack(it: Int) = this[size - 1 - it]


/**
 * Decodes an ULong from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded ULong and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [ULong.MAX_VALUE]
 */
inline fun Iterable<Byte>.decodeAsn1VarULong(): Pair<ULong, ByteArray> = iterator().decodeAsn1VarULong()

/**
 * Decodes an ULong from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded ULong and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [ULong.MAX_VALUE]
 */
inline fun ByteArray.decodeAsn1VarULong(): Pair<ULong, ByteArray> = iterator().decodeAsn1VarULong()

/**
 * Decodes an ULong from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded ULong and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [ULong.MAX_VALUE]
 */
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


//TOOD: how to not duplicate all this???
/**
 * Decodes an UInt from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded UInt and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [UInt.MAX_VALUE]
 */
inline fun Iterable<Byte>.decodeAsn1VarUInt(): Pair<UInt, ByteArray> = iterator().decodeAsn1VarUInt()

/**
 * Decodes an UInt from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded UInt and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [UInt.MAX_VALUE]
 */
inline fun ByteArray.decodeAsn1VarUInt(): Pair<UInt, ByteArray> = iterator().decodeAsn1VarUInt()

/**
 * Decodes an UInt from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded UInt and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [UInt.MAX_VALUE]
 */
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
