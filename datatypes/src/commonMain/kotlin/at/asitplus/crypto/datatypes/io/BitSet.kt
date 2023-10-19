package at.asitplus.crypto.datatypes.io

import kotlin.experimental.and
import kotlin.experimental.inv
import kotlin.experimental.or

private fun getByteIndex(i: Long) = (i / 8).toInt()
private fun getBitIndex(i: Long) = (i % 8).toInt()

private fun List<Byte>.getBit(index: Long): Boolean =
    if (index < 0) throw IndexOutOfBoundsException("index = $index")
    else kotlin.runCatching {
        this[getByteIndex(index)].getBit(getBitIndex(index))
    }.getOrElse { false }

private fun Byte.getBit(index: Int): Boolean =
    if (index < 0 || index > 7) throw IndexOutOfBoundsException("bit index $index out of bounds.")
    else (((1 shl index).toByte() and this) != 0.toByte())

/**
 * Pure Kotlin Bit Set created by throwing a bunch of extension functions at a `MutableList<Byte>`.
 * As a mental model: this BitSet grows from left to right, just like writing a text.
 *
 * **Note:** The in-byte bit index and the global index (for iterating over the bytes contained in the list) run in opposing directions!
 *
 * The [toBitString] function print our the bits as they are accessible, disragarding byte-alignment and memory layout:
 *
 * ```kotlin
 * val bitSet = KmmBitSet()
 * bitSet[0] = true //1             (ByteArray representation: [1])
 * bitSet[2] = true //101           (ByteArray representation: [5])
 * bitSet[8] = true //10100000 1    (ByteArray representation: [5,1])
 * ```
 *
 * To inspect the actual memory layout of the underlying bytes (i.e. the result of calling [toByteArray]), use [memDump]
 */
class KmmBitSet internal constructor(private val bytes: MutableList<Byte>) {
    constructor(nbits: Long = 0) : this(
        if (nbits < 0) throw IllegalArgumentException("a bit set of size $nbits makes no sense")
        else
            MutableList(getByteIndex(nbits) + 1) { 0.toByte() })


    operator fun get(index: Long): Boolean = bytes.getBit(index)

    fun nextSetBit(fromIndex: Long): Long {
        if (fromIndex < 0) throw IndexOutOfBoundsException("fromIndex = $fromIndex")

        val byteIndex = getByteIndex(fromIndex)

        if (byteIndex >= bytes.size) return -1
        else {
            bytes.subList(byteIndex, bytes.size).let { list ->
                val startIndex = getBitIndex(fromIndex).toLong()
                for (i: Long in startIndex until list.size.toLong() * 8L) {
                    if (list.getBit(i)) return byteIndex.toLong() * 8L + i
                }
            }
            return -1
        }
    }

    operator fun set(index: Long, value: Boolean) {
        val byteIndex = getByteIndex(index)
        while (bytes.size <= byteIndex) bytes.add(0)
        val byte = bytes[byteIndex]
        bytes[byteIndex] =
            if (value) {
                ((1 shl getBitIndex(index)).toByte() or byte)
            } else
                ((1 shl getBitIndex(index)).toByte().inv() and byte)
    }

    fun length(): Long = highestSetIndex() + 1L

    fun forEach(block: (it: Boolean) -> Unit) {
        for (i in 0..<length()) block(this[i])
    }

    inline fun forEachIndexed(block: (i: Long, it: Boolean) -> Unit) {
        for (i in 0..<length()) block(i, this[i])
    }

    fun forEachByte(block: (it: Byte) -> Unit) {
        if (bytes.isEmpty() || highestSetIndex() == -1L) return
        bytes.subList(0, getByteIndex(highestSetIndex()) + 1).forEach(block)
    }

    fun <T> mapByte(block: (it: Byte) -> T): List<T> {
        val list = mutableListOf<T>()
        forEachByte { list += block(it) }
        return list
    }

    fun toByteArray(): ByteArray {
        return if (bytes.isEmpty() || highestSetIndex() == -1L) byteArrayOf()
        else bytes.subList(0, getByteIndex(highestSetIndex()) + 1).toTypedArray().toByteArray()
    }

    private fun highestSetIndex(): Long {
        for (i: Long in bytes.size.toLong() * 8L - 1L downTo 0L) {
            if (bytes.getBit(i)) return i
        }
        return -1L
    }

    /**
     * Returns all bits as they are accessible by the global bit index
     *
     * Note that this representation conflicts with the usual binary representation of a bit-set's
     * underlying byte array for the following reason:
     *
     * Printing a byte array usually shows the MS*Byte* at the right-most position, but each byte's MS*Bit*
     * at a byte's individual left-most position, leading to bit and byte indices running in opposing directions.
     *
     * The string representation returned by this function can simply be interpreted as a list of boolean values
     * accessible by a monotonic index running in one direction.
     *
     * See the following illustration of memory layout vs. bit string index and the resulting string:
     * ```
     * ┌──────────────────────────────┐
     * │                              │
     * │                              │ Addr: 2
     * │      0  0  0  0  1  1  0  1       │
     * │   ◄─23─22─21─20─19─18─17─16─┐  │
     * │                           │  │
     * ├─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ┤
     * │                           │  │
     * │ ┌─────────────────────────┘  │ Addr: 1
     * │ │  1  0  0  0  1  0  0  0    │
     * │ └─15─14─12─12─11─10──9──8─┐  │
     * │                           │  │
     * ├─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ┤
     * │                           │  │
     * │ ┌─────────────────────────┘  │ Addr: 0
     * │ │  1  0  1  1  0  1  1  1    │
     * │ └──7──6──5──4──3──2──1──0──────index─◄─
     * │                              │
     * └──────────────────────────────┘
     *```
     *
     * This leads to the following bit string:
     * 11101101000100011011
     */
    fun toBitString() = toByteArray().toBitString()

    /**
     * Returns a binary representation of this bit set's memory layout, when packed into a byte array
     * Bytes are separated by a single space. An empty byte array results in an empty string.
     *
     * ```kotlin
     * val bits = BitSet()
     * bits[2] = true                   //00000100
     * bits[1] = true                   //00000110
     * bits[0] = true                   //00000111
     * bits[8] = true                   //00000111 00000001
     * ````
     */
    fun memDump() = toByteArray().memDump()


    override fun toString() = toBitString()
    override fun equals(other: Any?): Boolean {
        if (other == null) return false
        if (other::class != KmmBitSet::class) return false
        other as KmmBitSet
        forEachIndexed { i, it ->
            if (other[i] != it) return false
        }
        return true
    }

    companion object {
        /**
         * Wraps [bytes] into a BitSet. Copies all bytes.
         * Hence, modifications to [bytes] are **not** reflected in the newly created BitSet.
         */
        fun wrap(bytes: ByteArray) = bytes.toBitSet()

        fun fromBitString(bitString: String): KmmBitSet {
            if (bitString.isEmpty()) return KmmBitSet()
            if (!bitString.matches(Regex("^[01]+\$"))) throw IllegalArgumentException("Not a bit string")
            return KmmBitSet(bitString.length.toLong()).apply {
                bitString.forEachIndexed { i, it ->
                    this[i.toLong()] = (it == '1')
                }
            }
        }
    }
}

fun ByteArray.toBitSet(): KmmBitSet = KmmBitSet(toMutableList())


/**
 * Returns all bits as they are accessible by the global bit index (i.e. after wrapping this ByteArray into a BitSet)
 *
 * Note that this representation conflicts with the usual binary representation of a byte array for the following reason:
 *
 * Printing a byte array usually shows the MS*Byte* at the right-most position, but each byte's MS*Bit*
 * at a byte's individual left-most position, leading to bit and byte indices running in opposing directions.
 *
 * The string representation returned by this function can simply be interpreted as a list of boolean values
 * accessible by a monotonic index running in one direction.
 *
 * See the following illustration of memory layout vs. bit string index and the resulting string:
 * ```
 * ┌──────────────────────────────┐
 * │                              │
 * │                              │ Addr: 2
 * │      0  0  0  0  1  1  0  1       │
 * │   ◄─23─22─21─20─19─18─17─16─┐  │
 * │                           │  │
 * ├─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ┤
 * │                           │  │
 * │ ┌─────────────────────────┘  │ Addr: 1
 * │ │  1  0  0  0  1  0  0  0    │
 * │ └─15─14─12─12─11─10──9──8─┐  │
 * │                           │  │
 * ├─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ┤
 * │                           │  │
 * │ ┌─────────────────────────┘  │ Addr: 0
 * │ │  1  0  1  1  0  1  1  1    │
 * │ └──7──6──5──4──3──2──1──0──────index─◄─
 * │                              │
 * └──────────────────────────────┘
 *```
 *
 * This leads to the following bit string:
 * 11101101000100011011
 */
fun ByteArray.toBitString(): String =
    joinToString(separator = "") {
        it.toUByte().toString(2).padStart(8, '0').reversed()
    }.dropLastWhile { it == '0' }

/**
 * Returns a binary representation of this byte array's memory layout
 * Bytes are separated by a single space. An empty byte array results in an empty string.
 *
 * ```kotlin
 * byteArrayOf(4).memDump()         //00000100
 * byteArrayOf(7).memDump()         //00000111
 * byteArrayOf(17, 31).memDump()    //00010001 00011111
 * ````
 */
fun ByteArray.memDump(): String =
    joinToString(separator = " ") { it.toUByte().toString(2).padStart(8, '0') }