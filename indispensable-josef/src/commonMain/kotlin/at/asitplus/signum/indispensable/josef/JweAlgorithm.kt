package at.asitplus.signum.indispensable.josef

import at.asitplus.catching
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Suppress("SERIALIZER_TYPE_INCOMPATIBLE")
@Serializable(with = JweAlgorithmSerializer::class)
sealed class JweAlgorithm(override val identifier: String) : JsonWebAlgorithm {

    /**
     * ECDH-ES as per [RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037#section-3.2)
     */
    @Serializable(with = JweAlgorithmSerializer::class)
    object ECDH_ES : JweAlgorithm("ECDH-ES")

    @Serializable(with = JweAlgorithmSerializer::class)
    object A128KW : JweAlgorithm("A128KW")

    @Serializable(with = JweAlgorithmSerializer::class)
    object A192KW : JweAlgorithm("A192KW")

    @Serializable(with = JweAlgorithmSerializer::class)
    object A256KW : JweAlgorithm("A256KW")

    @Serializable(with = JweAlgorithmSerializer::class)
    object RSA_OAEP_256 : JweAlgorithm("RSA-OAEP-256")

    @Serializable(with = JweAlgorithmSerializer::class)
    object RSA_OAEP_384 : JweAlgorithm("RSA-OAEP-384")

    @Serializable(with = JweAlgorithmSerializer::class)
    object RSA_OAEP_512 : JweAlgorithm("RSA-OAEP-512")

    @Serializable(with = JweAlgorithmSerializer::class)
    class UNKNOWN(identifier: String) : JweAlgorithm(identifier)

    override fun toString() = "${this::class.simpleName}(identifier='$identifier')"

    companion object {
        val entries: Set<JweAlgorithm> by lazy {
            setOf(
                ECDH_ES,
                A128KW,
                A192KW,
                A256KW,
                RSA_OAEP_256,
                RSA_OAEP_384,
                RSA_OAEP_512,
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is JweAlgorithm) return false
        if (identifier != other.identifier) return false
        return true
    }

    override fun hashCode(): Int {
        return identifier.hashCode()
    }

}

object JweAlgorithmSerializer : KSerializer<JweAlgorithm> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JweAlgorithmSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JweAlgorithm) =
        JwaSerializer.serialize(encoder, value)

    override fun deserialize(decoder: Decoder): JweAlgorithm {
        val decoded = decoder.decodeString()
        return catching { JweAlgorithm.entries.first { it.identifier == decoded } }.getOrElse {
            JweAlgorithm.UNKNOWN(decoded)
        }
    }

}