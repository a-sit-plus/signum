package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.symmetric.SpecializedSymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import Enumerable
import Enumeration
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Suppress("SERIALIZER_TYPE_INCOMPATIBLE")
@Serializable(with = JweAlgorithmSerializer::class)
sealed class JweAlgorithm(override val identifier: String) : JsonWebAlgorithm, Enumerable {

    /**
     * ECDH-ES as per [RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037#section-3.2)
     */
    @Serializable(with = JweAlgorithmSerializer::class)
    object ECDH_ES : JweAlgorithm("ECDH-ES")

    sealed class Symmetric(identifier: String, override val algorithm: SymmetricEncryptionAlgorithm<*,*,*>)
        : JweAlgorithm(identifier), SpecializedSymmetricEncryptionAlgorithm {

        companion object : Enumeration<Symmetric> {
            override val entries: Set<Symmetric> by lazy {
                setOf(A128KW, A192KW, A256KW, A128GCMKW, A192GCMKW, A256GCMKW)
            }
        }
    }

    @Serializable(with = JweAlgorithmSerializer::class)
    object A128KW : JweAlgorithm.Symmetric("A128KW", SymmetricEncryptionAlgorithm.AES_128.WRAP.RFC3394)

    @Serializable(with = JweAlgorithmSerializer::class)
    object A192KW : JweAlgorithm.Symmetric("A192KW", SymmetricEncryptionAlgorithm.AES_192.WRAP.RFC3394)

    @Serializable(with = JweAlgorithmSerializer::class)
    object A256KW : JweAlgorithm.Symmetric("A256KW", SymmetricEncryptionAlgorithm.AES_256.WRAP.RFC3394)

    @Serializable(with = JweAlgorithmSerializer::class)
    object A128GCMKW : JweAlgorithm.Symmetric("A128GCMKW", SymmetricEncryptionAlgorithm.AES_128.GCM)

    @Serializable(with = JweAlgorithmSerializer::class)
    object A192GCMKW : JweAlgorithm.Symmetric("A192GCMKW", SymmetricEncryptionAlgorithm.AES_192.GCM)

    @Serializable(with = JweAlgorithmSerializer::class)
    object A256GCMKW : JweAlgorithm.Symmetric("A256GCMKW", SymmetricEncryptionAlgorithm.AES_256.GCM)

    @Serializable(with = JweAlgorithmSerializer::class)
    object RSA_OAEP_256 : JweAlgorithm("RSA-OAEP-256")

    @Serializable(with = JweAlgorithmSerializer::class)
    object RSA_OAEP_384 : JweAlgorithm("RSA-OAEP-384")

    @Serializable(with = JweAlgorithmSerializer::class)
    object RSA_OAEP_512 : JweAlgorithm("RSA-OAEP-512")

    @Serializable(with = JweAlgorithmSerializer::class)
    class UNKNOWN(identifier: String) : JweAlgorithm(identifier)

    override fun toString() = "${this::class.simpleName}(identifier='$identifier')"

    companion object : Enumeration<JweAlgorithm> {
        override val entries: Set<JweAlgorithm> by lazy {
            setOf(
                ECDH_ES,
                A128KW,
                A192KW,
                A256KW,
                A128GCMKW,
                A192GCMKW,
                A256GCMKW,
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

/**
 * Tries to map this algorithm to a matching [JsonWebAlgorithm] for key wrapping.
 * Mappings exist for the following algorithms (as others are not direct mappings of symmetric algorithms):
 * * [SymmetricEncryptionAlgorithm.AES.GCM]
 * * [SymmetricEncryptionAlgorithm.AES.WRAP]
 *
 *
 * @return `null` if no mapping exists
 */
fun SymmetricEncryptionAlgorithm<*, *, *>.toJweKwAlgorithm(): KmmResult<JweAlgorithm.Symmetric> = catching {
    when (this) {
        SymmetricEncryptionAlgorithm.AES_128.WRAP.RFC3394 -> JweAlgorithm.A128KW
        SymmetricEncryptionAlgorithm.AES_192.WRAP.RFC3394 -> JweAlgorithm.A192KW
        SymmetricEncryptionAlgorithm.AES_256.WRAP.RFC3394 -> JweAlgorithm.A256KW

        SymmetricEncryptionAlgorithm.AES_128.GCM -> JweAlgorithm.A128GCMKW
        SymmetricEncryptionAlgorithm.AES_192.GCM -> JweAlgorithm.A192GCMKW
        SymmetricEncryptionAlgorithm.AES_256.GCM -> JweAlgorithm.A256GCMKW

        else -> throw UnsupportedCryptoException("$this is not a a supported key wrapping algorithm for JWE")
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