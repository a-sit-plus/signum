package at.asitplus.signum.indispensable.cosef

import at.asitplus.catching
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Instant
import kotlinx.serialization.*
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborLabel

/**
 * CBOR Web Token (CWT)
 *
 * See [RFC8392](https://www.rfc-editor.org/rfc/rfc8392.html)
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class CborWebToken(
    /**
     * The "iss" (issuer) claim has the same meaning and processing rules as
     * the "iss" claim defined in Section 4.1.1 of RFC7519, except that
     * the value is a StringOrURI, as defined in Section 2 of this
     * specification.  The Claim Key 1 is used to identify this claim.
     */
    @CborLabel(1)
    @SerialName("iss")
    val issuer: String? = null,

    /**
     * The "sub" (subject) claim has the same meaning and processing rules
     * as the "sub" claim defined in Section 4.1.2 of RFC7519, except that
     * the value is a StringOrURI, as defined in Section 2 of this
     * specification.  The Claim Key 2 is used to identify this claim.
     */
    @CborLabel(2)
    @SerialName("sub")
    val subject: String? = null,

    /**
     * The "aud" (audience) claim has the same meaning and processing rules
     * as the "aud" claim defined in Section 4.1.3 of RFC7519, except that
     * the value of the audience claim is a StringOrURI when it is not an
     * array or each of the audience array element values is a StringOrURI
     * when the audience claim value is an array.  (StringOrURI is defined
     * in Section 2 of this specification.)  The Claim Key 3 is used to
     * identify this claim.
     */
    @CborLabel(3)
    @SerialName("aud")
    val audience: String? = null,

    /**
     * The "exp" (expiration time) claim has the same meaning and processing
     * rules as the "exp" claim defined in Section 4.1.4 of RFC7519,
     * except that the value is a NumericDate, as defined in Section 2 of
     * this specification.  The Claim Key 4 is used to identify this claim.
     */
    @CborLabel(4)
    @SerialName("exp")
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant? = null,

    /**
     * The "nbf" (not before) claim has the same meaning and processing
     * rules as the "nbf" claim defined in Section 4.1.5 of RFC7519,
     * except that the value is a NumericDate, as defined in Section 2 of
     * this specification.  The Claim Key 5 is used to identify this claim.
     */
    @CborLabel(5)
    @SerialName("nbf")
    @Serializable(with = InstantLongSerializer::class)
    val notBefore: Instant? = null,

    /**
     * The "iat" (issued at) claim has the same meaning and processing rules
     * as the "iat" claim defined in Section 4.1.6 of RFC7519, except that
     * the value is a NumericDate, as defined in Section 2 of this
     * specification.  The Claim Key 6 is used to identify this claim.
     */
    @CborLabel(6)
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant? = null,

    /**
     * The "cti" (CWT ID) claim has the same meaning and processing rules as
     * the "jti" claim defined in Section 4.1.7 of [RFC7519], except that
     * the value is a byte string.  The Claim Key 7 is used to identify this
     * claim.
     */
    @CborLabel(7)
    @SerialName("jti")
    @ByteString
    val cwtId: ByteArray? = null,

    @CborLabel(10)
    @SerialName("Nonce")
    @ByteString
    val nonce: ByteArray? = null,
) {

    fun serialize() = coseCompliantSerializer.encodeToByteArray(this)

    override fun toString(): String {
        return "CborWebToken(issuer=$issuer," +
                " subject=$subject," +
                " audience=$audience," +
                " expiration=$expiration," +
                " notBefore=$notBefore," +
                " issuedAt=$issuedAt," +
                " cwtId=${cwtId?.encodeToString(Base16Strict)}," +
                " nonce=${nonce?.encodeToString(Base16Strict)}" +
                ")"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CborWebToken

        if (issuer != other.issuer) return false
        if (subject != other.subject) return false
        if (audience != other.audience) return false
        if (expiration != other.expiration) return false
        if (notBefore != other.notBefore) return false
        if (issuedAt != other.issuedAt) return false
        if (cwtId != null) {
            if (other.cwtId == null) return false
            if (!cwtId.contentEquals(other.cwtId)) return false
        } else if (other.cwtId != null) return false
        if (nonce != null) {
            if (other.nonce == null) return false
            if (!nonce.contentEquals(other.nonce)) return false
        } else if (other.nonce != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = issuer?.hashCode() ?: 0
        result = 31 * result + (subject?.hashCode() ?: 0)
        result = 31 * result + (audience?.hashCode() ?: 0)
        result = 31 * result + (expiration?.hashCode() ?: 0)
        result = 31 * result + (notBefore?.hashCode() ?: 0)
        result = 31 * result + (issuedAt?.hashCode() ?: 0)
        result = 31 * result + (cwtId?.contentHashCode() ?: 0)
        result = 31 * result + (nonce?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(it: ByteArray) = catching {
            coseCompliantSerializer.decodeFromByteArray<CborWebToken>(it)
        }
    }
}