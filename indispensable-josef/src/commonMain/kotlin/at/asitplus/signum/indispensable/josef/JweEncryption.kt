package at.asitplus.signum.indispensable.josef

import at.asitplus.catching
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.supreme.symmetric.keyFrom
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
enum class JweEncryption(val identifier: String, val algorithm: SymmetricEncryptionAlgorithm<*, *, *>) {

    A128GCM("A128GCM", SymmetricEncryptionAlgorithm.AES_128.GCM),
    A192GCM("A192GCM", SymmetricEncryptionAlgorithm.AES_192.GCM),
    A256GCM("A256GCM", SymmetricEncryptionAlgorithm.AES_256.GCM),
    A128CBC_HS256("A128CBC-HS256", SymmetricEncryptionAlgorithm.AES_128.CBC.HMAC.SHA_256),
    A192CBC_HS384("A192CBC-HS384", SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_384),
    A256CBC_HS512("A256CBC-HS512", SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_512)
    ;


    @Deprecated("Clumsy name", ReplaceWith("identifier"))
    val text get() = identifier

    /**
     * For integrated AEAD algorithms, this is the length of the sole key.
     * For bolted-on AEAD algorithms with a dedicated MAC key, such as AES-CBC+HMAC,
     * this is the **length of the encryption key without the dedicated MAC key**.
     */
    val encryptionKeyLength: BitLength get() = algorithm.keySize

    val ivLength: BitLength
        get() = when (algorithm.requiresNonce()) {
            true -> algorithm.nonceTrait.length
            false -> 0.bit
        }

    /**
     * for integrated AEAD algorithms, this is zero.
     * For bolted-on AEAD algorithms with a dedicated MAC, this behaves as the name implies
     */
    val dedicatedMacKeyLength: BitLength get() = if (algorithm.hasDedicatedMac()) algorithm.preferredMacKeyLength else 0.bit

    /**
     * For integrated AEAD algorithms, this is the length of the sole key.
     * For bolted-on AEAD algorithms with a dedicated MAC key, such as AES-CBC+HMAC,
     * this is the **length of the encryption key plus the length dedicated MAC key**.
     */
    val combinedEncryptionKeyLength: BitLength get() = encryptionKeyLength + dedicatedMacKeyLength

    /**
     * Auth tag length. Should we support unauthenticated encryption algorithms, this would be zero.
     */
    val authTagLength: BitLength get() = if (algorithm.isAuthenticated()) algorithm.authTagLength else 0.bit

    /**
     * parses KWE key bytes for this algorithm and converts them to a [SymmetricKey].
     */
    fun symmetricKeyFromJsonWebKeyBytes(bytes: ByteArray) = catching {
        if (algorithm.hasDedicatedMac()) algorithm.keyFrom(
            bytes.drop(bytes.size / 2).toByteArray(),
            bytes.take(bytes.size / 2).toByteArray()
        ).getOrThrow()
        else algorithm.keyFrom(bytes).getOrThrow()
    }

}

object JweEncryptionSerializer : KSerializer<JweEncryption?> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JweEncryptionSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JweEncryption?) {
        value?.let { encoder.encodeString(it.identifier) }
    }

    override fun deserialize(decoder: Decoder): JweEncryption? {
        val decoded = decoder.decodeString()
        return JweEncryption.entries.firstOrNull { it.identifier == decoded }
    }
}

/**
 * Convenience conversion function to get a matching [JweEncryption] algorithm (if any).
 */
fun SymmetricEncryptionAlgorithm<*, *, *>.toJweEncryptionAlgorithm(): JweEncryption? =
    JweEncryption.entries.firstOrNull { it.algorithm == this }
