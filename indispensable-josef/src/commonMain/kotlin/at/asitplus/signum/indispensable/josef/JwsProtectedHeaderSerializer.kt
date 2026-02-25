package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object JwsProtectedHeaderSerializer : KSerializer<JwsHeader> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor(
        serialName = "JwsProtectedHeader",
        kind = PrimitiveKind.STRING,
    )

    override fun serialize(encoder: Encoder, value: JwsHeader) {
        encoder.encodeString(
            joseCompliantSerializer.encodeToString(JwsHeader.serializer(), value)
                .encodeToByteArray()
                .encodeToString(Base64UrlStrict)
        )
    }

    override fun deserialize(decoder: Decoder): JwsHeader {
        return joseCompliantSerializer.decodeFromString(
            JwsHeader.serializer(),
            decoder.decodeString().decodeToByteArray(Base64UrlStrict).decodeToString(),
        )
    }
}