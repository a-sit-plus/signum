package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.pki.CertificateChain
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
internal data class SigningHeader(
    @SerialName("alg")
    override val algorithm: JwsAlgorithm,
    @SerialName("kid")
    override val keyId: String? = null,
    val extension: String? = null,
    @SerialName("jwk")
    override val jsonWebKey: JsonWebKey? = null,
    @SerialName("typ")
    override val type: String? = null,
    @SerialName("cty")
    override val contentType: String? = null,
    @SerialName("x5u")
    override val certificateUrl: String? = null,
    @SerialName("x5t")
    @Serializable(ByteArrayBase64UrlSerializer::class)
    override val certificateSha1Thumbprint: ByteArray? = null,
    @SerialName("x5t#S256")
    @Serializable(ByteArrayBase64UrlSerializer::class)
    override val certificateSha256Thumbprint: ByteArray? = null,
    override val crit: List<String>? = null,
) : JwsHeader {
    @Transient
    override val certificateChain: CertificateChain? = null
    @Transient
    override val jsonWebKeySetUrl: String? = null
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SigningHeader

        if (algorithm != other.algorithm) return false
        if (keyId != other.keyId) return false
        if (extension != other.extension) return false
        if (jsonWebKey != other.jsonWebKey) return false
        if (type != other.type) return false
        if (contentType != other.contentType) return false
        if (certificateUrl != other.certificateUrl) return false
        if (!certificateSha1Thumbprint.contentEquals(other.certificateSha1Thumbprint)) return false
        if (!certificateSha256Thumbprint.contentEquals(other.certificateSha256Thumbprint)) return false
        if (crit != other.crit) return false
        if (certificateChain != other.certificateChain) return false
        if (jsonWebKeySetUrl != other.jsonWebKeySetUrl) return false

        return true
    }

    override fun hashCode(): Int {
        var result = algorithm.hashCode()
        result = 31 * result + keyId.hashCode()
        result = 31 * result + extension.hashCode()
        result = 31 * result + jsonWebKey.hashCode()
        result = 31 * result + type.hashCode()
        result = 31 * result + contentType.hashCode()
        result = 31 * result + certificateUrl.hashCode()
        result = 31 * result + (certificateSha1Thumbprint?.contentHashCode() ?: 0)
        result = 31 * result + (certificateSha256Thumbprint?.contentHashCode() ?: 0)
        result = 31 * result + crit.hashCode()
        result = 31 * result + certificateChain.hashCode()
        result = 31 * result + jsonWebKeySetUrl.hashCode()
        return result
    }
}

@Serializable
internal data class SigningPayload(val sub: String? = null)
