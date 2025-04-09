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
