package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.signum.indispensable.asn1.encoding.UVARINT_MASK_UBYTE
import at.asitplus.signum.indispensable.asn1.encoding.UVARINT_SINGLEBYTE_MAXVALUE
import at.asitplus.signum.indispensable.asn1.encoding.UVARINT_SINGLEBYTE_MAXVALUE_UBYTE
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlin.experimental.or
import kotlin.jvm.JvmInline

private val REGEX_BASE10 = Regex("[0-9]+")
private val REGEX_ZERO = Regex("0*")

@JvmInline
internal value class BigUInt(private val digits: MutableList<UByte> = mutableListOf<UByte>(0u)) {


    constructor(uInt: UInt) : this(uInt.toString())
    constructor(uLong: ULong) : this(uLong.toString())
    constructor(uByte: UByte) : this(mutableListOf(uByte))
    constructor(value: String) : this(value.convertToBytes())
    constructor(byteArray: ByteArray) : this(byteArray.map { it.toUByte() }.toMutableList())

    init {
        trim()
    }

    val bytes: List<UByte> get() = digits

    private fun trim() {
        digits.apply { while (digits.size > 1 && first() == 0.toUByte()) removeFirst() }
    }

    override fun toString() = digits.iterator().toDecimalString()
    fun toHexString() = StringBuilder().apply {
        digits.forEachIndexed { i, it ->
            append(
                it.toString(16).run { if (i > 0 && length < 2) "0$this" else this })
        }
    }.toString()

    fun toBinaryString() = StringBuilder().apply {
        digits.forEachIndexed { i, it ->
            it.toString(2).run {
                repeat(8 - length) { append('0') }
                append(this)
            }
        }
    }.dropWhile { it == '0' }.toString().let { if (it.isEmpty()) "0" else it }

    infix fun and(other: BigUInt): BigUInt {
        val (shorter, longer) = if (other.digits.size < digits.size) other to this else this to other
        val diff = longer.digits.size - shorter.digits.size
        return BigUInt(MutableList<UByte>(shorter.digits.size) {
            shorter.digits[it] and longer.digits[it + diff]
        }).apply { trim() }
    }

    infix fun or(other: BigUInt): BigUInt {
        val (shorter, longer) = if (other.digits.size < digits.size) other to this else this to other
        val diff = longer.digits.size - shorter.digits.size
        return BigUInt(MutableList<UByte>(longer.digits.size) {
            if (it >= diff) shorter.digits[it - diff] or longer.digits[it]
            else longer.digits[it]
        }).apply { trim() }
    }

    infix fun xor(other: BigUInt): BigUInt {
        val (shorter, longer) = if (other.digits.size < digits.size) other to this else this to other
        val diff = longer.digits.size - shorter.digits.size
        return BigUInt(MutableList<UByte>(longer.digits.size) {
            if (it >= diff) shorter.digits[it - diff] xor longer.digits[it]
            else longer.digits[it] xor 0u
        }).apply { trim() }
    }

    infix fun shl(offset: Int): BigUInt {
        //we us eit only internally require(offset >= 0) { "offset must be non-negative: $offset" }
        if (offset == 0) return BigUInt(digits.toMutableList())
        val byteOffset = offset / 8

        val bitOffset = offset % 8
        val result = MutableList<UByte>(digits.size + 1) { 0u }
        result.indices.drop(1).forEach { index ->
            val tmp = digits[index - 1].toInt() shl bitOffset
            val tmpH = (tmp ushr 8).toUByte()
            val tmpL = tmp.toUByte()
            result[index - 1] = result[index - 1] or tmpH
            result[index] = tmpL
        }
        return BigUInt(result.apply { repeat(byteOffset) { add(0u) } })
    }

    infix fun shr(offset: Int): BigUInt {
        //we use it only internally require(offset >= 0) { "offset must be non-negative: $offset" }
        if (offset == 0) return BigUInt(digits.toMutableList())
        val byteOffset = offset / 8
        if (byteOffset >= digits.size) return BigUInt()

        val bitOffset = offset % 8
        val dropped = digits.dropLast(byteOffset).toMutableList()

        val result = MutableList<UByte>(dropped.size) { 0u }
        result[result.lastIndex] = (dropped.last().toInt() ushr bitOffset).toUByte()
        for (index in result.lastIndex - 1 downTo 0) {
            val tmp = dropped[index].toInt() shl (8 - bitOffset)
            result[index] = tmp.ushr(8).toUByte()
            result[index + 1] = result[index + 1] or tmp.toUByte()
        }
        return BigUInt(result)
    }

    fun toAsn1VarInt(): ByteArray {
        if (digits.size == 1) {
            if (digits.first() == 0.toUByte()) return byteArrayOf(0)
            if (digits.first() < UVARINT_SINGLEBYTE_MAXVALUE_UBYTE) return byteArrayOf(
                digits.first().toByte()
            ) //Fast case}
        }

        val numBytes = (bitLength() + 6) / 7 // division rounding up
        val buf = Buffer()
        (numBytes - 1).downTo(0).forEach { byteIndex ->
            buf.writeByte(
                ((this shr (byteIndex * 7)).digits.last() and UVARINT_MASK_UBYTE).toByte() or
                        (if (byteIndex > 0) UVARINT_SINGLEBYTE_MAXVALUE else 0)
            )
        }
        //otherwise we won't ever write zero
        return buf.readByteArray()
    }


    fun isZero(): Boolean = (digits.size == 1 && digits.first() == 0.toUByte())

    fun bitLength(): Int {
        var result = digits.size * 8
        for (i in 7 downTo 0) {
            if (digits.first().toInt() and (1 shl i) == 0)
                result--
            else return result
        }
        return result
    }

    operator fun compareTo(byte: UByte): Int = if (digits.size > 1) 1 else digits.last().compareTo(byte)


    fun intValue(): Int =
        if (digits.size > 1) digits.last().toInt() and (digits[digits.lastIndex - 1].toInt() shl 8)
        else digits.last().toInt()


    companion object {
        private fun String.convertToBytes(): MutableList<UByte> {
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
            // Initialize the result as a StringBuilder to hold the base-10 value
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
        private infix fun List<Char>.decimalPlus(num2: List<Char>): MutableList<Char> {
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

        fun ByteArray.decodeAsn1VarBigUint() = iterator().decodeAsn1VarBigUInt()

        fun Iterator<Byte>.decodeAsn1VarBigUInt(): BigUInt {
            var result = BigUInt()
            val mask = 0x7Fu.toUByte()
            while (hasNext()) {
                val curByte = next()
                val current = (curByte.toUByte())
                result = BigUInt(current and mask) or (result shl 7)
                if (current < 0x80.toUByte()) break
            }
            return result
        }
    }
}

