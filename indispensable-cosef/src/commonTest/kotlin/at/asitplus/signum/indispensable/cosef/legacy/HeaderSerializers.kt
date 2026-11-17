@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.signum.indispensable.cosef.legacy

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.nullable
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

internal fun CoseHeader.toProtectedHeaderBytes(): ByteArray =
    coseCompliantSerializer.encodeToByteArray(CoseHeader.serializer(), this).let {
        if (it.contentEquals(byteArrayOf(0xA0.toByte()))) byteArrayOf() else it
    }
internal fun ByteArray.toProtectedCoseHeader(): CoseHeader =
    if (isEmpty()) CoseHeader() else coseCompliantSerializer.decodeFromByteArray(CoseHeader.serializer(), this)

object ProtectedCoseHeaderSerializer : KSerializer<CoseHeader> {
    override val descriptor = buildClassSerialDescriptor("LegacyProtectedHeader")
    override fun serialize(encoder: Encoder, value: CoseHeader) = encoder.encodeSerializableValue(ByteArraySerializer(), value.toProtectedHeaderBytes())
    override fun deserialize(decoder: Decoder) = decoder.decodeSerializableValue(ByteArraySerializer()).toProtectedCoseHeader()
}

object LegacyUnprotectedHeaderSerializer : KSerializer<CoseHeader?> {
    override val descriptor = CoseHeader.serializer().nullable.descriptor
    override fun serialize(encoder: Encoder, value: CoseHeader?) = encoder.encodeSerializableValue(CoseHeader.serializer(), value ?: CoseHeader())
    override fun deserialize(decoder: Decoder) = decoder.decodeSerializableValue(CoseHeader.serializer().nullable)
}
