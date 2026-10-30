package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.decodeIntOrText
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Value of the `content type` header parameter, a text string or an unsigned integer (`tstr / uint`).
 *
 * See [RFC 9052, Section 3.1](https://www.rfc-editor.org/rfc/rfc9052.html#section-3.1).
 */
@Serializable(with = CoseContentTypeSerializer::class)
sealed interface CoseContentType {

    /** Media type in the syntax `<type-name>/<subtype-name>` of RFC 6838, optionally with parameters. */
    data class MediaType(val value: String) : CoseContentType

    /** Identifier from the IANA "CoAP Content-Formats" registry. */
    data class ContentFormat(val value: Int) : CoseContentType {
        init {
            require(value >= 0) { "Content format must be an unsigned integer" }
        }
    }
}

object CoseContentTypeSerializer : KSerializer<CoseContentType> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("CoseContentType", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: CoseContentType) = when (value) {
        is CoseContentType.ContentFormat -> encoder.encodeInt(value.value)
        is CoseContentType.MediaType -> encoder.encodeString(value.value)
    }

    override fun deserialize(decoder: Decoder): CoseContentType =
        decoder.decodeIntOrText({ CoseContentType.ContentFormat(it) }, { CoseContentType.MediaType(it) })
}
