package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.authTagLength
import at.asitplus.signum.indispensable.symmetric.hasDedicatedMac
import at.asitplus.signum.indispensable.symmetric.requiresNonce
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


    val encryptionKeyLength: BitLength get() = algorithm.keySize

    val ivLength: BitLength
        get() = when (algorithm.requiresNonce()) {
            true -> algorithm.nonceTrait.length
            false -> 0.bit
        }

    /**
     * Per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.3),
     * where the MAC output bytes need to be truncated to this size for use in JWE.
     */
    val macLength: Int?
        get() = when (algorithm.hasDedicatedMac()) {
            true -> algorithm.authTagLength.bits.toInt() / 2
            false -> null
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
