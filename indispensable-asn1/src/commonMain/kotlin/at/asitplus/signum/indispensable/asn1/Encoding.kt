package at.asitplus.signum.indispensable.asn1

import kotlinx.io.*
import kotlinx.io.unsafe.UnsafeBufferOperations

/**
 * Directly moves the byte array to a buffer without copying. Thus, it keeps bytes managed by a Buffer accessible.
 * The bytes may be overwritten through the Buffer or even recycled to be used by another buffer.
 * Therefore, operating on these bytes after wrapping leads to undefined behaviour.
 */
@UnsafeIoApi
fun ByteArray.wrapInUnsafeSource(): Source = Buffer().apply {
    UnsafeBufferOperations.moveToTail(this, this@wrapInUnsafeSource)
}

/**
 * Directly moves the byte array to a buffer without copying. Thus, it keeps bytes managed by a Buffer accessible.
 * The bytes may be overwritten through the Buffer or even recycled to be used by another buffer.
 * Therefore, operating on these bytes after wrapping leads to undefined behaviour.
 * [startIndex] is inclusive, [endIndex] is exclusive.
 */
@UnsafeIoApi
internal fun wrapInUnsafeSource(bytes: ByteArray, startIndex: Int = 0, endIndex: Int = bytes.size) = Buffer().apply {
    require(startIndex in 0..endIndex) { "StartIndex bust be between 0 and $endIndex" }
    UnsafeBufferOperations.moveToTail(this, bytes, startIndex, endIndex)
}

/**
 * Helper to create a buffer, operate on it and return its contents as a [ByteArray]
 */
internal inline fun throughBuffer(operation: (Buffer) -> Unit): ByteArray =
    Buffer().also(operation).readByteArray()

@OptIn(UnsafeIoApi::class)
internal inline fun <reified T> ByteArray.throughBuffer(operation: (Source) -> T): T =
    operation(wrapInUnsafeSource())


/**
 * Directly appends [bytes] to this Sink's internal Buffer without copying. Thus, it keeps bytes managed by a Buffer accessible.
 * The bytes may be overwritten through the Buffer or even recycled to be used by another buffer.
 * Therefore, operating on these bytes after wrapping leads to undefined behaviour.
 * [startIndex] is inclusive, [endIndex] is exclusive.
 */
@OptIn(DelicateIoApi::class, UnsafeIoApi::class)
internal fun Sink.appendUnsafe(bytes: ByteArray, startIndex: Int = 0, endIndex: Int = bytes.size): Int {
    require(startIndex in 0..<endIndex) { "StartIndex must be between 0 and $endIndex" }
    writeToInternalBuffer {
        UnsafeBufferOperations.moveToTail(it, bytes, startIndex, endIndex)
    }
    return endIndex - startIndex
}