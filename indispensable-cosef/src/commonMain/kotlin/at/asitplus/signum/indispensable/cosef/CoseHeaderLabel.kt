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
 * Label of a COSE header parameter, an integer or a text string (`label = int / tstr`).
 *
 * See [RFC 9052, Section 3](https://www.rfc-editor.org/rfc/rfc9052.html#section-3).
 */
@Serializable(with = CoseHeaderLabelSerializer::class)
sealed interface CoseHeaderLabel {
    data class Numeric(val value: Int) : CoseHeaderLabel
    data class Text(val value: String) : CoseHeaderLabel
}

object CoseHeaderLabelSerializer : KSerializer<CoseHeaderLabel> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("CoseHeaderLabel", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: CoseHeaderLabel) = when (value) {
        is CoseHeaderLabel.Numeric -> encoder.encodeInt(value.value)
        is CoseHeaderLabel.Text -> encoder.encodeString(value.value)
    }

    override fun deserialize(decoder: Decoder): CoseHeaderLabel =
        decoder.decodeIntOrText({ CoseHeaderLabel.Numeric(it) }, { CoseHeaderLabel.Text(it) })
}
