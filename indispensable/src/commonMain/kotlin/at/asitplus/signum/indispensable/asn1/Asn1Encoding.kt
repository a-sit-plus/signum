package at.asitplus.signum.indispensable.asn1

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.io.BitSet
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.util.toTwosComplementByteArray
import kotlinx.datetime.Instant
import kotlin.experimental.or

/**
 * Class Providing a DSL for creating arbitrary ASN.1 structures. You will almost certainly never use it directly, but rather use it as follows:
 * ```kotlin
 * Sequence {
 *     +Tagged(1uL) {
 *         +Asn1Primitive(BERTags.BOOLEAN.toUlong(), byteArrayOf(0x00))
 *     }
 *     +Set {
 *         +Sequence {
 *             +SetOf {
 *                 +PrintableString("World")
 *                 +PrintableString("Hello")
 *             }
 *             +Set {
 *                 +PrintableString("World")
 *                 +PrintableString("Hello")
 *                 +Utf8String("!!!")
 *             }
 *
 *         }
 *     }
 *     +Null()
 *
 *     +ObjectIdentifier("1.2.603.624.97")
 *
 *     +Utf8String("Foo")
 *     +PrintableString("Bar")
 *
 *     +Set {
 *         +Int(3)
 *         +Long(-65789876543L)
 *         +Bool(false)
 *         +Bool(true)
 *     }
 *     +Sequence {
 *         +Null()
 *         +Asn1String.Numeric("12345")
 *         +UtcTime(instant)
 *     }
 * }
 * ```
 */
class Asn1TreeBuilder {
    internal val elements = mutableListOf<Asn1Element>()

    /**
     * appends a single [Asn1Element] to this ASN.1 structure
     */
    operator fun Asn1Element.unaryPlus() {
        elements += this
    }

    /**
     * appends a single [Asn1Encodable] to this ASN.1 structure
     * @throws Asn1Exception in case encoding constraints of children are violated
     */
    @Throws(Asn1Exception::class)
    operator fun Asn1Encodable<*>.unaryPlus() {
        +encodeToTlv()
    }
}

/**
 * Namespace object for ASN.1 builder DSL functions and utility functions for creating ASN.1 primitives
 */
object Asn1 {
    /**
     * Creates a new SEQUENCE as [Asn1Sequence].
     * Use as follows:
     *
     * ```kotlin
     * Sequence {
     *   +Null()
     *   +PrintableString("World")
     *   +PrintableString("Hello")
     *   +Utf8String("!!!")
     * }
     *  ```
     */
    fun Sequence(root: Asn1TreeBuilder.() -> Unit): Asn1Sequence {
        val seq = Asn1TreeBuilder()
        seq.root()
        return Asn1Sequence(seq.elements)
    }


    /**
     * Exception-free version of [Sequence]
     */
    fun SequenceOrNull(root: Asn1TreeBuilder.() -> Unit) =
        catching { Sequence(root) }.getOrNull()


    /**
     * Safe version of [Sequence], wrapping the result into a [KmmResult]
     */
    fun SequenceSafe(root: Asn1TreeBuilder.() -> Unit) = catching { Sequence(root) }


    /**
     * Creates a new  SET as [Asn1Set]. Elements are sorted by tag.
     * Use as follows:
     *
     * ```kotlin
     * Set {
     *   +Null()
     *   +PrintableString("World")
     *   +PrintableString("Hello")
     *   +Utf8String("!!!")
     * }
     *  ```
     */
    fun Set(root: Asn1TreeBuilder.() -> Unit): Asn1Set {
        val seq = Asn1TreeBuilder()
        seq.root()
        return Asn1Set(seq.elements)
    }

    /**
     * Exception-free version of [Set]
     */
    fun SetOrNull(root: Asn1TreeBuilder.() -> Unit) = catching { Set(root) }.getOrNull()


    /**
     * Safe version of [Set], wrapping the result into a [KmmResult]
     */
    fun SetSafe(root: Asn1TreeBuilder.() -> Unit) = catching { Set(root) }


    /**
     * Creates a new SET OF as [Asn1Set]. Tags of all added elements need to be the same. Elements are sorted by encoded value
     * Use as follows:
     *
     * ```kotlin
     * SetOf {
     *   +PrintableString("World")
     *   +PrintableString("!!!")
     *   +PrintableString("Hello")
     * }
     *  ```
     *
     *  @throws Asn1Exception if children of different tags are added
     */
    @Throws(Asn1Exception::class)
    fun SetOf(root: Asn1TreeBuilder.() -> Unit): Asn1Set {
        val seq = Asn1TreeBuilder()
        seq.root()
        return Asn1SetOf(seq.elements)
    }

    /**
     * Exception-free version of [SetOf]
     */
    fun SetOfOrNull(root: Asn1TreeBuilder.() -> Unit) = catching { SetOf(root) }.getOrNull()


    /**
     * Safe version of [SetOf], wrapping the result into a [KmmResult]
     */
    fun SetOfSafe(root: Asn1TreeBuilder.() -> Unit) = catching { SetOf(root) }


    /**
     * Creates a new EXPLICITLY TAGGED ASN.1 structure as [Asn1Tagged] using [tag].
     *
     * Use as follows:
     *
     * ```kotlin
     * Tagged(2uL) {
     *   +PrintableString("World World")
     *   +Null()
     *   +Int(1337)
     * }
     *  ```
     */
    fun Tagged(tag: ULong, root: Asn1TreeBuilder.() -> Unit): Asn1Tagged {
        val seq = Asn1TreeBuilder()
        seq.root()
        return Asn1Tagged(tag, seq.elements)
    }

    /**
     * Exception-free version of [Tagged]
     */
    fun TaggedOrNull(tag: ULong, root: Asn1TreeBuilder.() -> Unit) =
        catching { Tagged(tag, root) }.getOrNull()

    /**
     * Safe version on [Tagged], wrapping the result into a [KmmResult]
     */
    fun TaggedSafe(tag: ULong, root: Asn1TreeBuilder.() -> Unit) =
        catching { Tagged(tag, root) }


    /**
     * Adds a BOOL [Asn1Primitive] to this ASN.1 structure
     */
    fun Bool(value: Boolean) = value.encodeToTlv()


    /**
     * Adds an INTEGER [Asn1Primitive] to this ASN.1 structure
     */
    fun Int(value: Int) = value.encodeToTlv()


    /**
     * Adds an INTEGER [Asn1Primitive] to this ASN.1 structure
     */
    fun Int(value: Long) = value.encodeToTlv()


    /**
     * Adds the passed bytes as OCTET STRING [Asn1Element] to this ASN.1 structure
     */
    fun OctetString(bytes: ByteArray) = bytes.encodeToTlvOctetString()


    /**
     * Adds the passed bytes as BIT STRING [Asn1Primitive] to this ASN.1 structure
     */
    fun BitString(bytes: ByteArray) = bytes.encodeToTlvBitString()


    /**
     * Transforms the passed BitSet as BIT STRING [Asn1Primitive] to this ASN.1 structure.
     * **Left-Aligned and right-padded (see [Asn1BitString])**
     */
    fun BitString(bitSet: BitSet) = Asn1BitString(bitSet).encodeToTlv()

    /**
     * Adds the passed string as UTF8 STRING [Asn1Primitive] to this ASN.1 structure
     */
    fun Utf8String(value: String) = Asn1String.UTF8(value).encodeToTlv()


    /**
     * Adds the passed string as PRINTABLE STRING [Asn1Primitive] to this ASN.1 structure
     *
     * @throws Asn1Exception if illegal characters are to be encoded into a printable string
     */
    @Throws(Asn1Exception::class)
    fun PrintableString(value: String) = Asn1String.Printable(value).encodeToTlv()


    /**
     * Adds a NULL [Asn1Primitive] to this ASN.1 structure
     */
    fun Null() = Asn1Primitive(Asn1Element.Tag.NULL, byteArrayOf())


    /**
     * Adds the passed instant as UTC TIME [Asn1Primitive] to this ASN.1 structure
     */
    fun UtcTime(value: Instant) = value.encodeToAsn1UtcTime()


    /**
     * Adds the passed instant as GENERALIZED TIME [Asn1Primitive] to this ASN.1 structure
     */
    fun GeneralizedTime(value: Instant) = value.encodeToAsn1GeneralizedTime()


    /**
     * OCTET STRING builder. The result of [init] is encapsulated into an ASN.1 OCTET STRING and then added to this ASN.1 structure
     * ```kotlin
     *   OctetStringEncapsulating {
     *       +PrintableString("Hello")
     *       +PrintableString("World")
     *       +Sequence {
     *         +PrintableString("World")
     *         +PrintableString("Hello")
     *         +Utf8String("!!!")
     *       }
     *     }
     *  ```
     */
    fun OctetStringEncapsulating(init: Asn1TreeBuilder.() -> Unit): Asn1EncapsulatingOctetString {
        val seq = Asn1TreeBuilder()
        seq.init()
        return Asn1EncapsulatingOctetString(seq.elements)
    }

}

/**
 * Produces an INTEGER as [Asn1Primitive]
 */
fun Int.encodeToTlv() = Asn1Primitive(Asn1Element.Tag.INT, encodeToDer())


/**
 * Produces a BOOLEAN as [Asn1Primitive]
 */
fun Boolean.encodeToTlv() = Asn1Primitive(Asn1Element.Tag.BOOL, byteArrayOf(if (this) 0xff.toByte() else 0))

/**
 * Produces an INTEGER as [Asn1Primitive]
 */
fun Long.encodeToTlv() = Asn1Primitive(Asn1Element.Tag.INT, encodeToDer())

/**
 * Produces an INTEGER as [Asn1Primitive]
 */
fun BigInteger.encodeToTlv() = Asn1Primitive(Asn1Element.Tag.INT, toTwosComplementByteArray())

/**
 * Produces an OCTET STRING as [Asn1Primitive]
 */
fun ByteArray.encodeToTlvOctetString() = Asn1PrimitiveOctetString(this)

/**
 * Produces a BIT STRING as [Asn1Primitive]
 */
fun ByteArray.encodeToTlvBitString() = Asn1Primitive(Asn1Element.Tag.BIT_STRING, encodeToBitString())

/**
 * Prepends 0x00 to this ByteArray for encoding it into a BIT STRING. Useful for implicit tagging
 */
fun ByteArray.encodeToBitString() = byteArrayOf(0x00) + this

internal fun Int.encodeToDer() = if (this == 0) byteArrayOf(0) else
    toTwosComplementByteArray()

private fun Long.encodeToDer() = if (this == 0L) byteArrayOf(0) else
    toTwosComplementByteArray()

/**
 * Produces a UTC TIME as [Asn1Primitive]
 */
fun Instant.encodeToAsn1UtcTime() =
    Asn1Primitive(Asn1Element.Tag.TIME_UTC, encodeToAsn1Time().drop(2).encodeToByteArray())

/**
 * Produces a GENERALIZED TIME as [Asn1Primitive]
 */
fun Instant.encodeToAsn1GeneralizedTime() =
    Asn1Primitive(Asn1Element.Tag.TIME_GENERALIZED, encodeToAsn1Time().encodeToByteArray())

private fun Instant.encodeToAsn1Time(): String {
    val value = this.toString()
    if (value.isEmpty())
        throw IllegalArgumentException("Instant serialization failed: no value")
    val matchResult = Regex("([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})")
        .matchAt(value, 0)
        ?: throw IllegalArgumentException("Instant serialization failed: $value")
    val year = matchResult.groups[1]?.value
        ?: throw IllegalArgumentException("Instant serialization year failed: $value")
    val month = matchResult.groups[2]?.value
        ?: throw IllegalArgumentException("Instant serialization month failed: $value")
    val day = matchResult.groups[3]?.value
        ?: throw IllegalArgumentException("Instant serialization day failed: $value")
    val hour = matchResult.groups[4]?.value
        ?: throw IllegalArgumentException("Instant serialization hour failed: $value")
    val minute = matchResult.groups[5]?.value
        ?: throw IllegalArgumentException("Instant serialization minute failed: $value")
    val seconds = matchResult.groups[6]?.value
        ?: throw IllegalArgumentException("Instant serialization seconds failed: $value")
    return "$year$month$day$hour$minute$seconds" + "Z"
}

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

/** Encodes a signed Long to a minimum-size twos-complement byte array */
fun Long.toTwosComplementByteArray(): ByteArray {
    //fast case
    if (this >= Byte.MIN_VALUE && this <= Byte.MAX_VALUE) return byteArrayOf(this.toByte())
    if (this >= Short.MIN_VALUE && this <= Short.MAX_VALUE) return byteArrayOf(
        (this ushr 8).toByte(),
        this.toByte()
    )
    if (this >= -(0x80 shl 16) && this < (0x80 shl 16)) return byteArrayOf(
        (this ushr 16).toByte(),
        (this ushr 8).toByte(),
        this.toByte()
    )
    if (this >= -((0x80L shl 24)) && this < (0x80L shl 24)) return byteArrayOf(
        (this ushr 24).toByte(),
        (this ushr 16).toByte(),
        (this ushr 8).toByte(),
        this.toByte()
    )
    if (this >= Int.MIN_VALUE && this <= Int.MAX_VALUE) return byteArrayOf(
        (this ushr 32).toByte(),
        (this ushr 24).toByte(),
        (this ushr 16).toByte(),
        (this ushr 8).toByte(),
        this.toByte()
    )

    if (this >= -((0x80L shl 40)) && this < (0x80L shl 40)) return byteArrayOf(
        (this ushr 40).toByte(),
        (this ushr 32).toByte(),
        (this ushr 24).toByte(),
        (this ushr 16).toByte(),
        (this ushr 8).toByte(),
        this.toByte()
    )
    if (this >= -((0x80L shl 48)) && this < (0x80L shl 48)) return byteArrayOf(
        (this ushr 48).toByte(),
        (this ushr 40).toByte(),
        (this ushr 32).toByte(),
        (this ushr 24).toByte(),
        (this ushr 16).toByte(),
        (this ushr 8).toByte(),
        this.toByte()
    )
    return byteArrayOf(
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
 * Drops bytes at the start, or adds zero bytes at the start, until the [size] is reached
 */
fun ByteArray.ensureSize(size: Int): ByteArray = (this.size - size).let { toDrop ->
    when {
        toDrop > 0 -> this.copyOfRange(toDrop, this.size)
        toDrop < 0 -> ByteArray(-toDrop) + this
        else -> this
    }
}

@Suppress("NOTHING_TO_INLINE")
inline fun ByteArray.ensureSize(size: UInt) = ensureSize(size.toInt())

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

    return ByteArray(result.size){
        result[result.size-1-it] or  (if (it < result.size-1) 0x80 else 0x00).toByte()
    }
}

//TODO: how to not duplicate this withut wasting bytes?
/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
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

    return ByteArray(result.size){
        result[result.size-1-it] or  (if (it < result.size-1) 0x80 else 0x00).toByte()
    }
}