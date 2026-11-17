package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import kotlinx.serialization.KSerializer

/**
 * If [this] is a [ByteArray], use it as is, otherwise encode it as a [ByteStringWrapper], with CBOR tag 24
 */
internal fun <P : Any> P?.toRawPayload(payloadSerializer: KSerializer<P>): ByteArray? =
    this?.let { encodePayload(it, payloadSerializer) }

internal fun ByteArray.wrapInCborTag(tag: Byte) = byteArrayOf(0xd8.toByte()) + byteArrayOf(tag) + this