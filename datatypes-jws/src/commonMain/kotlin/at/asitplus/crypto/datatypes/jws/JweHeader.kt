package at.asitplus.crypto.datatypes.jws

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.io.ByteArrayBase64UrlSerializer
import at.asitplus.crypto.datatypes.jws.io.jsonSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * Header of a [JweEncrypted] or [JweDecrypted].
 *
 * See [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)
 */
@Serializable
data class JweHeader(
    @SerialName("alg")
    val algorithm: JweAlgorithm?,
    @SerialName("enc")
    val encryption: JweEncryption?,
    @SerialName("kid")
    val keyId: String? = null,
    @SerialName("typ")
    val type: String?,
    @SerialName("cty")
    val contentType: String? = null,
    @SerialName("jwk")
    val jsonWebKey: JsonWebKey? = null,
    @SerialName("epk")
    val ephemeralKeyPair: JsonWebKey? = null,
    @SerialName("apu")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val agreementPartyUInfo: ByteArray? = null,
    @SerialName("apv")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val agreementPartyVInfo: ByteArray? = null,
) {
    fun serialize() = jsonSerializer.encodeToString(this)
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JweHeader

        if (algorithm != other.algorithm) return false
        if (encryption != other.encryption) return false
        if (keyId != other.keyId) return false
        if (type != other.type) return false
        if (contentType != other.contentType) return false
        if (jsonWebKey != other.jsonWebKey) return false
        if (ephemeralKeyPair != other.ephemeralKeyPair) return false
        if (agreementPartyUInfo != null) {
            if (other.agreementPartyUInfo == null) return false
            if (!agreementPartyUInfo.contentEquals(other.agreementPartyUInfo)) return false
        } else if (other.agreementPartyUInfo != null) return false
        if (agreementPartyVInfo != null) {
            if (other.agreementPartyVInfo == null) return false
            if (!agreementPartyVInfo.contentEquals(other.agreementPartyVInfo)) return false
        } else if (other.agreementPartyVInfo != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = algorithm?.hashCode() ?: 0
        result = 31 * result + (encryption?.hashCode() ?: 0)
        result = 31 * result + (keyId?.hashCode() ?: 0)
        result = 31 * result + (type?.hashCode() ?: 0)
        result = 31 * result + (contentType?.hashCode() ?: 0)
        result = 31 * result + (jsonWebKey?.hashCode() ?: 0)
        result = 31 * result + (ephemeralKeyPair?.hashCode() ?: 0)
        result = 31 * result + (agreementPartyUInfo?.contentHashCode() ?: 0)
        result = 31 * result + (agreementPartyVInfo?.contentHashCode() ?: 0)
        return result
    }


    val publicKey: JsonWebKey? by lazy {
        jsonWebKey ?: keyId?.let { JsonWebKey.fromDid(it).getOrNull() }
    }

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<JweHeader>(it)
        }.wrap()
    }
}