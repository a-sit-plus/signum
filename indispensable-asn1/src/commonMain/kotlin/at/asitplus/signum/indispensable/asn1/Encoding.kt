package at.asitplus.signum.indispensable.asn1

import kotlinx.io.*
import kotlinx.io.unsafe.UnsafeBufferOperations

@OptIn(UnsafeIoApi::class)
fun ByteArray.wrapInUnsafeSource(): Source = Buffer().apply {
    UnsafeBufferOperations.moveToTail(this, this@wrapInUnsafeSource)
}

/**
 * Directly moves the byte array to a buffer without copying. Thus, it keeps bytes managed by a Buffer accessible.
 * The bytes may be overwritten through the Buffer or even recycled to be used by another buffer.
 * Therefore, operating on these bytes after wrapping leads to undefined behaviour.
 * [startIndex] is inclusive, [endIndex] is exclusive.
 */
@OptIn(UnsafeIoApi::class)
internal fun wrapInUnsafeSource(bytes: ByteArray, startIndex: Int = 0, endIndex: Int = bytes.size) = Buffer().apply {
    require(startIndex in 0..endIndex) { "StartIndex bust be between 0 and $endIndex" }
    UnsafeBufferOperations.moveToTail(this, bytes, startIndex, endIndex)
}

/**
 * Helper to create a buffer, operate on it and return its contents as a [ByteArray]
 */
inline fun throughBuffer(operation: (Buffer) -> Unit): ByteArray =
    Buffer().also(operation).readByteArray()

inline fun <reified T> ByteArray.throughBuffer(operation: (Source) -> T): T =
    wrapInUnsafeSource().let { operation(it) }


/**
 * Directly appends [bytes] to this Sink's internal Buffer without copying. Thus, it keeps bytes managed by a Buffer accessible.
 * The bytes may be overwritten through the Buffer or even recycled to be used by another buffer.
 * Therefore, operating on these bytes after wrapping leads to undefined behaviour.
 * [startIndex] is inclusive, [endIndex] is exclusive.
 */
internal fun Sink.appendUnsafe(bytes: ByteArray, startIndex: Int = 0, endIndex: Int = bytes.size): Int {
    require(startIndex in 0..<endIndex) { "StartIndex must be between 0 and $endIndex" }
    writeToInternalBuffer {
        UnsafeBufferOperations.moveToTail(it, bytes, startIndex, endIndex)
    }
    return endIndex - startIndex
}

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
