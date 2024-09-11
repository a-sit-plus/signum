package at.asitplus.signum.indispensable.josef

import at.asitplus.catching
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToString
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Structure to declare posession of a particular proof-of-possesion key,
 * to be included in [JsonWebToken.confirmationClaim]
 *
 * See [RFC 7800](https://datatracker.ietf.org/doc/html/rfc7800)
 */
@Serializable
data class ConfirmationClaim(
    /**
     * RFC 7800: When the key held by the presenter is an asymmetric private key, the
     * [jsonWebKey] member is a [JsonWebKey] representing the corresponding
     * asymmetric public key.
     */
    @SerialName("jwk")
    val jsonWebKey: JsonWebKey? = null,

    /**
     * RFC 7800: When the key held by the presenter is a symmetric key, the [encryptedSymmetricKey]
     * member is an encrypted [JsonWebKey] encrypted to a key known to
     * the recipient using the JWE Compact Serialization containing the
     * symmetric key.
     */
    @SerialName("jwe")
    @Serializable(JweEncryptedSerializer::class)
    val encryptedSymmetricKey: JweEncrypted? = null,

    /**
     * RFC 7800:  The proof-of-possession key can also be identified by the use of a
     * Key ID instead of communicating the actual key, provided the
     * recipient is able to obtain the identified key using the Key ID.
     */
    @SerialName("kid")
    val keyId: String? = null,

    /**
     * RFC 7800: The proof-of-possession key can be passed by reference instead of
     * being passed by value.  This is done using the "jku" member.  Its
     * value is a URI (`RFC3986`) that refers to a resource for a set of JSON-
     * encoded public keys represented as a [JsonWebKeySet], one of which is
     * the proof-of-possession key.  If there are multiple keys in the
     * referenced JWK Set document, a [keyId] member MUST also be included
     * with the referenced key's JWK also containing the same [keyId] value.
     */
    @SerialName("jku")
    val jsonWebKeySetUrl: String? = null,

    /**
     * RFC 9449: JWK SHA-256 Thumbprint confirmation method. The value of the [jsonWebKeyThumbprint] member MUST be the
     * base64url encoding (as defined in `RFC7515`) of the JWK SHA-256 Thumbprint (according to `RFC7638`) of the DPoP
     * public key (in JWK format) to which the access token is bound.
     *
     * See also [JsonWebKey.jwkThumbprint]
     */
    @SerialName("jkt")
    val jsonWebKeyThumbprint: String? = null,
) {

    fun serialize() = joseCompliantSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = catching {
            joseCompliantSerializer.decodeFromString<ConfirmationClaim>(it)
        }
    }
}


object JweEncryptedSerializer : KSerializer<JweEncrypted> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JweEncryptedSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JweEncrypted) {
        encoder.encodeString(value.serialize())
    }

    override fun deserialize(decoder: Decoder): JweEncrypted {
        return JweEncrypted.parse(decoder.decodeString()).getOrThrow()
    }
}