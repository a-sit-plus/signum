package at.asitplus.crypto.datatypes.jws

import at.asitplus.crypto.datatypes.asn1.ObjectIdentifier
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = JweAlgorithmSerializer::class)
enum class JweAlgorithm(override val identifier: String) : JsonWebAlgorithm {

    /**
     * ECDH-ES as per [RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037#section-3.2)
     */
    ECDH_ES("ECDH-ES"),
    A128KW("A128KW"),
    A192KW("A192KW"),
    A256KW("A256KW"),
    RSA_OAEP_256("RSA-OAEP-256"),
    RSA_OAEP_384("RSA-OAEP-384"),
    RSA_OAEP_512("RSA-OAEP-512")
}

object JweAlgorithmSerializer : KSerializer<JweAlgorithm> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JweAlgorithmSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JweAlgorithm) = JwaSerializer.serialize(encoder, value)

    override fun deserialize(decoder: Decoder): JweAlgorithm {
        val decoded = decoder.decodeString()
        return JweAlgorithm.entries.first { it.identifier == decoded }
    }

}