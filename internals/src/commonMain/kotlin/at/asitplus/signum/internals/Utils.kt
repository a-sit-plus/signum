package at.asitplus.signum.internals

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
