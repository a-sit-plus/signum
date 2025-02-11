package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.Asn1Integer.Companion.fromTwosComplement
import at.asitplus.signum.indispensable.asn1.VarUInt.Companion.decimalPlus
import at.asitplus.signum.indispensable.asn1.encoding.UVARINT_MASK_UBYTE
import at.asitplus.signum.indispensable.asn1.encoding.UVARINT_SINGLEBYTE_MAXVALUE
import at.asitplus.signum.indispensable.asn1.encoding.bitLength
import at.asitplus.signum.indispensable.asn1.encoding.decodeToAsn1Integer
import at.asitplus.signum.indispensable.asn1.encoding.toTwosComplementByteArray
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1Primitive
import kotlinx.io.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.experimental.or
import kotlin.jvm.JvmInline

private val REGEX_BASE10 = Regex("[0-9]+")
private val REGEX_ZERO = Regex("0*")

fun Asn1Integer(number: Int) = Asn1Integer(number.toLong())
fun Asn1Integer(number: Long) =
    if (number < 0) Asn1Integer.Negative(VarUInt((number * -1).toULong()))
    else Asn1Integer.Positive(VarUInt((number).toULong()))
fun Asn1Integer(number: UInt) = Asn1Integer(number.toULong())
fun Asn1Integer(number: ULong) =
    Asn1Integer.Positive(VarUInt(number))

/**
 * A very simple implementation of an ASN.1 variable-length integer.
 * It is only good for reading from and writing to ASN.1 structures. It is not a BigInt, nor does it define any operations.
 * It has a [sign] though, and supports [twosComplement] representation and converting [fromTwosComplement].
 * Hence, it directly interoperates with [Kotlin MP BigNum](https://github.com/ionspin/kotlin-multiplatform-bignum) and the JVM BigInteger.
 */
@Serializable(with = Asn1IntegerSerializer::class)
sealed class Asn1Integer(internal val uint: VarUInt, val sign: Sign): Asn1Encodable<Asn1Primitive> {

    override fun encodeToTlv(): Asn1Primitive = encodeToAsn1Primitive()

    enum class Sign {
        POSITIVE,
        NEGATIVE
    }

    override fun toString(): String = when (sign) {
        Sign.POSITIVE -> uint.toString()
        Sign.NEGATIVE -> "-${uint}"
    }

    /** Encodes the [Asn1Integer] to its minimum-size twos-complement encoding. Non-empty. */
    abstract fun twosComplement(): ByteArray

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Asn1Integer) return false

        if (sign != other.sign) return false
        return (uint.isEqualTo(other.uint))
    }

    override fun hashCode(): Int {
        var result = uint.words.contentHashCode()
        result = 31 * result + sign.hashCode()
        return result
    }

    fun isZero() = uint.isZero()

    /** The minimum-size unsigned bytearray encoding of this number's absolute value. Non-empty. */
    val magnitude by lazy { uint.bytes.asByteArray() }

    class Positive internal constructor(uint: VarUInt) : Asn1Integer(uint, Sign.POSITIVE) {
        override fun twosComplement(): ByteArray = uint.bytes.let {
            if (it.first().countLeadingZeroBits() == 0) listOf(0.toUByte()) + it else it
        }.toUByteArray().asByteArray()

        /** The number of bits required to represent this value */
        fun bitLength() = uint.bitLength().toUInt()
    }

    class Negative internal constructor(uint: VarUInt) : Asn1Integer(uint, Sign.NEGATIVE) {
        init {
            check(!uint.isZero()) // there is no negative zero
        }
        override fun twosComplement(): ByteArray {
            if (uint == VarUInt(1u)) return byteArrayOf(-1)

            return VarUInt(
                uint.inv().toString().toMutableList().decimalPlus(listOf('1')).joinToString(separator = "")
            ).bytes.let {
                val diff = uint.bytes.size - it.size
                val list = if (diff == 0) it else (MutableList<UByte>(diff) { 0.toUByte() }) + it
                if (list.first().toByte() >= 0) listOf((-1).toUByte()) + list
                else it
            }.toUByteArray().asByteArray()
        }
    }

    companion object: Asn1Decodable<Asn1Primitive, Asn1Integer> {
        val ONE = Asn1Integer.Positive(VarUInt(1u))
        val ZERO = Asn1Integer.Positive(VarUInt(0u))

        /** Constructs an [Asn1Integer] from a decimal string */
        fun fromDecimalString(input: String): Asn1Integer {
            require(input.isNotEmpty())
            val (numericPart, sign) = when {
                input.first() == '-' -> Pair(input.substring(1), Sign.NEGATIVE)
                else -> Pair(input, Sign.POSITIVE)
            }
            require(numericPart.matches(REGEX_BASE10)) { "NaN: $input" }
            return fromSignMagnitude(VarUInt(numericPart), sign)
        }

        private fun fromSignMagnitude(magnitude: VarUInt, sign: Sign) = when {
            sign == Sign.POSITIVE || magnitude.isZero() -> Positive(magnitude)
            else -> Negative(magnitude)
        }

        /** Constructs an [Asn1Integer] from its sign-magnitude representation */
        fun fromByteArray(magnitude: ByteArray, sign: Sign) =
            fromSignMagnitude(VarUInt(magnitude), sign)

        /** Constructs a non-negative [Asn1Integer] from its unsigned magnitude representation */
        fun fromUnsignedByteArray(magnitude: ByteArray) = Positive(VarUInt(magnitude))

        /** Constructs an [Asn1Integer] from its twos-complement byte representation */
        fun fromTwosComplement(input: ByteArray): Asn1Integer = when {
            input.isEmpty() -> Positive(VarUInt())
            (input.first() < 0) ->
                Negative(
                    VarUInt(
                        VarUInt(input).inv().toString().toMutableList().decimalPlus(listOf('1'))
                            .joinToString(separator = "")
                    )
                )

            else -> Positive(VarUInt(input))
        }

        override fun doDecode(src: Asn1Primitive): Asn1Integer = src.decodeToAsn1Integer()
    }
}

// ?????????????????????????????????????????????????????????????????????????????????????????????
// ??? WHY DOES THIS NOT EXIST IN THE STANDARD LIBRARY ????? ????? ????? ????? ????? ????? ?????
// ?????????????????????????????????????????????????????????????????????????????????????????????
private inline infix fun UByte.shr(bitCount: Int) =
    (toUInt() shr bitCount).toUByte()

private inline infix fun UByte.shl(bitCount: Int) =
    (toUInt() shl bitCount).toUByte()

private inline fun combine(highByte: UByte, lowByte: UByte, highBits: Int) =
    ((highByte.toUInt() shl (8-highBits)) or (lowByte.toUInt() shr highBits)).toUByte()



@JvmInline
internal value class VarUInt private constructor(val words: UByteArray) {

    init {
        check(!words.isEmpty())
        check((words.size == 1) || (words.first() != 0x00u.toUByte()))
    }

    inline fun isEqualTo(other: VarUInt) = (words contentEquals other.words)

    val bytes get() = words.copyOf()

    override fun toString() = words.iterator().toDecimalString()
    fun toHexString() = StringBuilder().apply {
        words.forEachIndexed { i, it ->
            append(
                it.toString(16).run { if (i > 0 && length < 2) "0$this" else this })
        }
    }.toString()

    infix fun and(other: VarUInt): VarUInt {
        val (shorter, longer) = if (other.words.size < words.size) other to this else this to other
        val diff = longer.words.size - shorter.words.size
        return constructFromUntrimmed(UByteArray(shorter.words.size) {
            shorter.words[it] and longer.words[it + diff]
        }, isOwned = true)
    }

    infix fun or(other: VarUInt): VarUInt {
        val (shorter, longer) = if (other.words.size < words.size) other to this else this to other
        val diff = longer.words.size - shorter.words.size
        return VarUInt(UByteArray(longer.words.size) {
            if (it >= diff) shorter.words[it - diff] or longer.words[it]
            else longer.words[it]
        })
    }

    infix fun xor(other: VarUInt): VarUInt {
        val (shorter, longer) = if (other.words.size < words.size) other to this else this to other
        val diff = longer.words.size - shorter.words.size
        return constructFromUntrimmed(UByteArray(longer.words.size) {
            if (it >= diff) shorter.words[it - diff] xor longer.words[it]
            else longer.words[it]
        }, isOwned = true)
    }

    infix fun shl(offset: Int): VarUInt {
        require(offset >= 0) { "offset must be non-negative: $offset" }
        if ((offset == 0) || this.isZero()) return this

        val highWordBits = 8-(offset % 8)
        if (highWordBits == 8) return VarUInt(words.copyOf(words.size + (offset/8)))

        val newSize = words.size + (offset/8) + 1

        return constructFromUntrimmed(UByteArray(newSize) { i ->
            when {
                i == 0 -> words[i] shr highWordBits
                i < words.size -> combine(words[i-1], words[i], highWordBits)
                i == words.size -> words[i-1] shl 8-highWordBits
                else -> 0x00u
            }
        }, isOwned = true)
    }

    infix fun shr(offset: Int): VarUInt {
        require(offset >= 0) { "offset must be non-negative: $offset" }
        if ((offset == 0) || this.isZero()) return this

        val newSize = words.size - (offset / 8)
        if (newSize <= 0) return ZERO

        val highWordBits = offset % 8
        if (highWordBits == 0) return VarUInt(words.copyOfRange(0, newSize))
        return constructFromUntrimmed(UByteArray(newSize) { i -> when {
            i > 0 -> combine(words[i-1], words[i], highWordBits)
            else -> words[i] shr highWordBits
        }}, true)
    }

    fun toAsn1VarInt(): ByteArray = throughBuffer { it.writeAsn1VarInt(this) }

    fun isZero(): Boolean = (words.first() == 0.toUByte()) //always trimmed, so it is enough to inspect the first byte

    fun bitLength(): Int = 8*(words.size-1) + words.first().bitLength

    fun inv(): VarUInt = constructFromUntrimmed(UByteArray(words.size) { words[it].inv() }, true)


    operator fun compareTo(byte: UByte): Int = if (words.size > 1) 1 else words.last().compareTo(byte)


    /**
     * @throws IllegalArgumentException if the number is too large
     */
    @Throws(IllegalArgumentException::class)
    fun shortValue(): Int =
        if(words.size>2) throw IllegalArgumentException("Number too large!")
        else if (words.size > 1) words.last().toInt() and (words[words.lastIndex - 1].toInt() shl 8)
        else words.last().toInt()


    companion object {
        val ZERO = VarUInt(ubyteArrayOf(0x00u))

        private fun constructFromUntrimmed(untrimmed: UByteArray, isOwned: Boolean): VarUInt {
            val i = untrimmed.indexOfFirst { it != 0x00u.toUByte() }
            return when {
                (i == -1) -> ZERO
                (i == 0 && isOwned) -> VarUInt(untrimmed)
                else -> VarUInt(untrimmed.copyOfRange(i, untrimmed.size))
            }
        }

        operator fun invoke(uByte: UByte = 0x00u) = constructFromUntrimmed(ubyteArrayOf(uByte), true)
        operator fun invoke(value: String) = constructFromUntrimmed(value.parseAsBase10().toUByteArray(), true)
        operator fun invoke(ubyteArray: UByteArray) = constructFromUntrimmed(ubyteArray, false)
        operator fun invoke(byteArray: ByteArray) = constructFromUntrimmed(byteArray.asUByteArray(), false)
        operator fun invoke(uLong: ULong) = constructFromUntrimmed(uLong.toTwosComplementByteArray().asUByteArray(), true)
        operator fun invoke(uInt: UInt) = constructFromUntrimmed(uInt.toTwosComplementByteArray().asUByteArray(), true)

        internal fun constructUnsafe(ownedArray: UByteArray) = constructFromUntrimmed(ownedArray, true)

        internal fun Sink.writeAsn1VarInt(number: VarUInt): Int {
            if (number.isZero()) {
                writeByte(0)
                return 1
            }
            val numBytes = (number.bitLength() + 6) / 7 // division rounding up

            (numBytes - 1).downTo(0).forEach { byteIndex ->
                writeByte(
                    ((number shr (byteIndex * 7)).words.last() and UVARINT_MASK_UBYTE).toByte() or
                            (if (byteIndex > 0) UVARINT_SINGLEBYTE_MAXVALUE else 0)
                )
            }
            return numBytes
        }

        private fun MutableList<Char>.divRem(d: Int) : Pair<MutableList<Char>, Int> {
            val result = mutableListOf<Char>()
            var residue = 0
            // result * 256 + residue == (string[0..i])
            for (char in this) {
                val currentDigit = residue * 10 + char.digitToInt()
                result.add((currentDigit / d).digitToChar()) // Append the quotient
                residue = currentDigit % d // Update remainder
            }
            result.apply { while (isNotEmpty() && first() == '0') removeFirst() }
            return Pair(result, residue)
        }

        private fun String.parseAsBase10(): UByteArray {
            if (!matches(REGEX_BASE10)) throw Asn1Exception("Illegal input!")
            if (matches(REGEX_ZERO)) return ubyteArrayOf(0x00u)
            var currentValue = toMutableList()
            val byteList = mutableListOf<UByte>()
            while ((currentValue.size > 1) || (currentValue.size == 1 && currentValue.first() != '0')) {
                currentValue.divRem(256).let { (newValue, rem) ->
                    currentValue = newValue
                    byteList.add(rem.toUByte())
                }
            }
            return UByteArray(byteList.size) { byteList[byteList.size-it-1] }
        }


        private fun Iterator<UByte>.toDecimalString(): String {
            // Initialize the result to hold the base-10 value
            var decimalResult = mutableListOf('0')

            // Process each byte in the base-256 array
            for (byte in this) {
                // Convert byte to an integer (unsigned)
                val value = byte.toInt() and 0xFF

                // Multiply the current decimal result by 256
                decimalResult = decimalResult.times256()

                // Add the new value
                decimalResult = decimalResult decimalPlus value.toString().toList()
            }

            return decimalResult.joinToString(separator = "")
        }

        // Function to multiply a large base-10 number (as a string) by 256
        private fun List<Char>.times256(): MutableList<Char> {
            var carry = 0
            val result = StringBuilder()

            for (digit in asReversed()) {
                val prod = digit.digitToInt() * 256 + carry
                result.append(prod % 10)
                carry = prod / 10
            }

            // Add remaining carry
            while (carry > 0) {
                result.append(carry % 10)
                carry /= 10
            }

            return result.reverse().toMutableList()
        }

        // Function to add two large base-10 numbers (as strings)
        internal infix fun List<Char>.decimalPlus(num2: List<Char>): MutableList<Char> {
            val result = StringBuilder()
            var carry = 0

            val (shorter, longer) = (if (size < num2.size) this to num2
            else num2 to this).let { (a, b) -> a.asReversed() to b.asReversed() }

            for (i in longer.indices) {
                val sum = (if (shorter.size > i) shorter[i].digitToInt() else 0) + longer[i].digitToInt() + carry
                result.append(sum % 10)
                carry = sum / 10
            }

            // Add remaining carry
            while (carry > 0) {
                result.append(carry % 10)
                carry /= 10
            }

            return result.reverse().toMutableList()
        }

        internal fun ByteArray.decodeAsn1VarBigUInt() = wrapInUnsafeSource().decodeAsn1VarBigUInt().first

        internal fun Source.decodeAsn1VarBigUInt(): Pair<VarUInt, ByteArray> {
            val accumulator = Buffer()
            var result = VarUInt()
            val mask = 0x7Fu.toUByte()
            while (!exhausted()) {
                val current = readUByte()
                accumulator.writeUByte(current)
                result = VarUInt(current and mask) or (result shl 7)
                if (current < 0x80.toUByte()) break
            }
            return result to accumulator.readByteArray()
        }
    }
}

object Asn1IntegerSerializer : KSerializer<Asn1Integer> {
    override val descriptor = PrimitiveSerialDescriptor("ASN.1 Integer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Asn1Integer =
        Asn1Integer.fromDecimalString(decoder.decodeString())


    override fun serialize(encoder: Encoder, value: Asn1Integer) {
        encoder.encodeString(value.toString())
    }

}