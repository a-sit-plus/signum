package at.asitplus.signum.internals

import kotlin.experimental.xor

infix fun <T: Any> T?.orLazy(block: ()->T) = if (this != null) lazyOf(this) else lazy(block)

/** Drops bytes at the start, or adds zero bytes at the start, until the [size] is reached */
fun ByteArray.ensureSize(size: Int): ByteArray = (this.size - size).let { toDrop ->
    when {
        toDrop > 0 -> this.copyOfRange(toDrop, this.size)
        toDrop < 0 -> ByteArray(-toDrop) + this
        else -> this
    }
}

@Suppress("NOTHING_TO_INLINE")
inline fun ByteArray.ensureSize(size: UInt) = ensureSize(size.toInt())

@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
inline fun <@kotlin.internal.OnlyInputTypes O, reified T : O> checkedAs(v: O): T =
    v as? T
        ?: throw IllegalArgumentException("Expected type was ${T::class.simpleName}, but was really ${if (v == null) "<null>" else v!!::class.simpleName}")

inline fun <I, O, reified T : O> checkedAsFn(crossinline fn: (I) -> O): (I) -> T = {
    checkedAs(fn(it))
}

infix fun ByteArray.xor(other: ByteArray): ByteArray {
    check(this.size == other.size)
    return ByteArray(this.size) { i -> this[i] xor other[i] }
}

class ImplementationError(message: String?=null): Throwable("$message\nThis is an implementation error. Please report this bug at https://github.com/a-sit-plus/signum/issues/new/")

fun ByteArray.padStart(toSize: Int, pad: Byte = 0x00) = when {
    this.size < toSize -> (ByteArray(toSize - this.size) { pad } + this)
    else -> this
}

fun ByteArray.padStart(toSize: UInt, pad: Byte = 0x00) =
    padStart(toSize.toInt(), pad)


class ByteArrayView(private val a: ByteArray, private val off: Int = 0, val size: Int = a.size-off) {
    private val end get() = off+size

    init { require((0 <= this.off) && (this.end <= a.size)) }

     operator fun get(i: Int) = a[off+i]
     operator fun set(i: Int, v: Byte) { a[off+i] = v }

    fun subview(off: Int, sz: Int): ByteArrayView {
        require(off+sz <= this.size)
        return ByteArrayView(a, this.off+off, sz)
    }

    fun copyOf() = a.copyOfRange(off, end)
    fun replaceWith(other: ByteArrayView) { require(size == other.size); other.a.copyInto(a, off, other.off, other.end) }
    fun xor_inplace(other: ByteArrayView) { require (size <= other.size); repeat(size) { this[it] = this[it] xor other[it] }}
}
 fun ByteArray.subview(off: Int, sz: Int): ByteArrayView = ByteArrayView(this, off, sz)
 val ByteArray.view get() = ByteArrayView(this)

 fun ByteArrayView.toUIntArrayLE(buf: UIntArray) {
    check(buf.size*4 == this.size)
    repeat(buf.size) { i ->
        buf[i] = (this[i*4+3].toUByte().toUInt() shl 24) or
                (this[i*4+2].toUByte().toUInt() shl 16) or
                (this[i*4+1].toUByte().toUInt() shl 8) or
                (this[i*4+0].toUByte().toUInt() shl 0)
    }
}

 fun UIntArray.toLEByteArray(buf: ByteArrayView) {
    check(buf.size == this.size*4)
    repeat(buf.size) { i ->
        buf[i] = (this[i/4] shr (i%4)*8).toByte()
    }
}

fun Int.isPowerOfTwo() = (this > 0) && ((this and (this-1)) == 0)
