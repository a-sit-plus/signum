package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import kotlinx.serialization.KSerializer

/**
 * If [this] is a [ByteArray], use it as is, otherwise encode it as a [ByteStringWrapper], with CBOR tag 24
 */
internal fun <P : Any> P?.toRawPayload(payloadSerializer: KSerializer<P>): ByteArray? = when (this) {
    is ByteArray -> this
    is Nothing -> null
    is ByteStringWrapper<*> -> throw IllegalArgumentException("Payload must not be a ByteStringWrapper")
    is P -> coseCompliantSerializer.encodeToByteArray<ByteStringWrapper<P>>(
        ByteStringWrapperSerializer(payloadSerializer),
        ByteStringWrapper(this)
    ).wrapInCborTag(24)

    else -> null
}

private fun ByteArray.wrapInCborTag(tag: Byte) = byteArrayOf(0xd8.toByte()) + byteArrayOf(tag) + this
