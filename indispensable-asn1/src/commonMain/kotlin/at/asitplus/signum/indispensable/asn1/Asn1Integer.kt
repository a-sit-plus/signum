package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.Asn1Integer.Companion.fromTwosComplement
import at.asitplus.signum.indispensable.asn1.VarUInt.Companion.decimalPlus
import at.asitplus.signum.indispensable.asn1.encoding.UVARINT_MASK_UBYTE
import at.asitplus.signum.indispensable.asn1.encoding.UVARINT_SINGLEBYTE_MAXVALUE
import at.asitplus.signum.indispensable.asn1.encoding.bitLength
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

/**
 * A very simple implementation of an ASN.1 variable-length integer.
 * It is only good for reading from and writing to ASN.1 structures. It is not a BigInt, nor does it define any operations.
 * It has a [sign] though, and supports [twosComplement] representation and converting [fromTwosComplement].
 * Hence, it directly interoperates with [Kotlin MP BigNum](https://github.com/ionspin/kotlin-multiplatform-bignum) and the JVM BigInteger.
 */
@Serializable(with = Asn1IntegerSerializer::class)
sealed class Asn1Integer(internal val uint: VarUInt, private val sign: Sign) {

    enum class Sign {
        POSITIVE,
        NEGATIVE
    }

    override fun toString(): String = when (sign) {
        Sign.POSITIVE -> uint.toString()
        Sign.NEGATIVE -> "-${uint}"
    }

    abstract fun twosComplement(): ByteArray
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Asn1Integer) return false

        if (uint != other.uint) return false
        if (sign != other.sign) return false

        return true
    }

    override fun hashCode(): Int {
        var result = uint.hashCode()
        result = 31 * result + sign.hashCode()
        return result
    }

    class Positive internal constructor(uint: VarUInt) : Asn1Integer(uint, Sign.POSITIVE) {
        override fun twosComplement(): ByteArray = uint.bytes.let {
            if (it.first().countLeadingZeroBits() == 0) listOf(0.toUByte()) + it else it
        }.toUByteArray().toByteArray()
    }

    class Negative internal constructor(uint: VarUInt) : Asn1Integer(uint, Sign.NEGATIVE) {
        override fun twosComplement(): ByteArray {
            if (uint == VarUInt(1u)) return byteArrayOf(-1)

            return VarUInt(
                uint.inv().toString().toMutableList().decimalPlus(listOf('1')).joinToString(separator = "")
            ).bytes.let {
                val diff = uint.bytes.size - it.size
                val list = if (diff == 0) it else mutableListOf(0.toUByte()) + it
                if (list.first().toByte() >= 0) listOf((-1).toUByte()) + list
                else it
            }.toUByteArray().toByteArray()
        }
    }

    companion object {
        val ONE = Asn1Integer.Positive(VarUInt(1u))
        val ZERO = Asn1Integer.Positive(VarUInt(0u))

        fun fromDecimalString(input: String): Asn1Integer {
            if (input.matches(REGEX_BASE10)) return Positive(VarUInt(input))
            if (input.first() == '-' && input.substring(1).matches(REGEX_BASE10))
                return Negative(VarUInt(input.substring(1)))
            else throw IllegalArgumentException("NaN: $input")
        }

        fun fromTwosComplement(input: ByteArray): Asn1Integer =
            if (input.first() < 0) {
                Negative(
                    VarUInt(
                        VarUInt(input).inv().toString().toMutableList().decimalPlus(listOf('1'))
                            .joinToString(separator = "")
                    )
                )
            } else Positive(VarUInt(input))
    }
}


@JvmInline
internal value class VarUInt(private val words: MutableList<UByte> = mutableListOf(0u)) {


    constructor(uInt: UInt) : this(uInt.toString())
    constructor(uLong: ULong) : this(uLong.toString())
    constructor(uByte: UByte) : this(mutableListOf(uByte))
    constructor(value: String) : this(value.parseAsBase10())
    constructor(byteArray: ByteArray) : this(byteArray.map { it.toUByte() }.toMutableList())

    init {
        trim()
    }

    val bytes: List<UByte> get() = words

    private fun trim() {
        words.apply { while (words.size > 1 && first() == 0.toUByte()) removeFirst() }
    }

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
        return VarUInt(MutableList<UByte>(shorter.words.size) {
            shorter.words[it] and longer.words[it + diff]
        }).apply { trim() }
    }

    infix fun or(other: VarUInt): VarUInt {
        val (shorter, longer) = if (other.words.size < words.size) other to this else this to other
        val diff = longer.words.size - shorter.words.size
        return VarUInt(MutableList<UByte>(longer.words.size) {
            if (it >= diff) shorter.words[it - diff] or longer.words[it]
            else longer.words[it]
        }).apply { trim() }
    }

    infix fun xor(other: VarUInt): VarUInt {
        val (shorter, longer) = if (other.words.size < words.size) other to this else this to other
        val diff = longer.words.size - shorter.words.size
        return VarUInt(MutableList<UByte>(longer.words.size) {
            if (it >= diff) shorter.words[it - diff] xor longer.words[it]
            else longer.words[it]
        })
    }

    infix fun shl(offset: Int): VarUInt {
        require(offset >= 0) { "offset must be non-negative: $offset" }
        if (offset == 0) return VarUInt(words.toMutableList())
        val byteOffset = offset / 8

        val bitOffset = offset % 8
        val result = MutableList<UByte>(words.size + 1) { 0u }
        result.indices.drop(1).forEach { index ->
            val tmp = words[index - 1].toInt() shl bitOffset
            val tmpH = (tmp ushr 8).toUByte()
            val tmpL = tmp.toUByte()
            result[index - 1] = result[index - 1] or tmpH
            result[index] = tmpL
        }
        return VarUInt(result.apply { repeat(byteOffset) { add(0u) } })
    }

    infix fun shr(offset: Int): VarUInt {
        //we use it only internally require(offset >= 0) { "offset must be non-negative: $offset" }
        if (offset == 0) return VarUInt(words.toMutableList())
        val byteOffset = offset / 8
        if (byteOffset >= words.size) return VarUInt()

        val bitOffset = offset % 8
        val dropped = words.dropLast(byteOffset).toMutableList()

        val result = MutableList<UByte>(dropped.size) { 0u }
        result[result.lastIndex] = (dropped.last().toInt() ushr bitOffset).toUByte()
        for (index in result.lastIndex - 1 downTo 0) {
            val tmp = dropped[index].toInt() shl (8 - bitOffset)
            result[index] = tmp.ushr(8).toUByte()
            result[index + 1] = result[index + 1] or tmp.toUByte()
        }
        return VarUInt(result)
    }

    fun toAsn1VarInt(): ByteArray = throughBuffer { it.writeAsn1VarInt(this) }

    fun isZero(): Boolean = (words.first() == 0.toUByte()) //always trimmed, so it is enough to inspect the first byte

    fun bitLength(): Int = 8*(words.size-1) + words.first().toUInt().bitLength

    fun inv(): VarUInt = VarUInt(MutableList(words.size) { words[it].inv() })


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

        private fun String.parseAsBase10(): MutableList<UByte> {
            if (!matches(REGEX_BASE10)) throw Asn1Exception("Illegal input!")
            if (matches(REGEX_ZERO)) return mutableListOf(0u)
            var currentValue = toMutableList()
            val byteList = mutableListOf<UByte>()
            var resultBuffer = mutableListOf<Char>()
            var residue: Int
            while ((currentValue.size > 1) || (currentValue.size == 1 && currentValue.first() != '0')) {
                resultBuffer.clear()
                residue = 0
                for (char in currentValue) {
                    val currentDigit = residue * 10 + char.digitToInt()
                    resultBuffer.add((currentDigit / 256).digitToChar()) // Append the quotient
                    residue = currentDigit % 256 // Update remainder
                }
                // swap
                val tmp = currentValue
                currentValue = resultBuffer.apply { while (isNotEmpty() && first() == '0') removeFirst() }
                resultBuffer = tmp
                //end swap
                byteList.add(0, residue.toUByte())
            }
            return byteList
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