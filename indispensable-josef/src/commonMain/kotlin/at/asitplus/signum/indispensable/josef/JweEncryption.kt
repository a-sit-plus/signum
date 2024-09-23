package at.asitplus.signum.indispensable.josef

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Supported JWE algorithms.
 *
 * See [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)
 * and also [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)
 */
@Serializable(with = JweEncryptionSerializer::class)
enum class JweEncryption(val text: String) {

    A128GCM("A128GCM"),
    A192GCM("A192GCM"),
    A256GCM("A256GCM"),
    A128CBC_HS256("A128CBC-HS256"),
    A192CBC_HS384("A192CBC-HS384"),
    A256CBC_HS512("A256CBC-HS512")
    ;

    val encryptionKeyLength
        get() = when (this) {
            A128GCM -> 128
            A192GCM -> 192
            A256GCM -> 256
            A128CBC_HS256 -> 256
            A192CBC_HS384 -> 384
            A256CBC_HS512 -> 512
        }

    val ivLengthBits
        get() = when (this) {
            A128GCM, A192GCM, A256GCM -> 128 // all AES-based
            A128CBC_HS256, A192CBC_HS384, A256CBC_HS512 -> 128 // all AES-based
        }

    /**
     * Per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.3),
     * where the MAC output bytes need to be truncated to this size for use in JWE.
     */
    val macLength: Int?
        get() = when (this) {
            A128CBC_HS256 -> 16
            A192CBC_HS384 -> 24
            A256CBC_HS512 -> 32
            else -> null
        }
}

object JweEncryptionSerializer : KSerializer<JweEncryption?> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JweEncryptionSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JweEncryption?) {
        value?.let { encoder.encodeString(it.text) }
    }

    override fun deserialize(decoder: Decoder): JweEncryption? {
        val decoded = decoder.decodeString()
        return JweEncryption.entries.firstOrNull { it.text == decoded }
    }
}

