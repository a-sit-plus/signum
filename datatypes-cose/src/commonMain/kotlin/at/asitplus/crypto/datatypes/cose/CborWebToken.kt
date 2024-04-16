package at.asitplus.crypto.datatypes.cose

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.cose.io.Base16Strict
import at.asitplus.crypto.datatypes.cose.io.cborSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Instant
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborLabel
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * RFC 8392: CBOR Web Token (CWT)
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class CborWebToken(
    @CborLabel(1)
    @SerialName("iss")
    val issuer: String? = null,
    @CborLabel(2)
    @SerialName("sub")
    val subject: String? = null,
    @CborLabel(3)
    @SerialName("aud")
    val audience: String? = null,
    @CborLabel(4)
    @SerialName("exp")
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant? = null,
    @CborLabel(5)
    @SerialName("nbf")
    @Serializable(with = InstantLongSerializer::class)
    val notBefore: Instant? = null,
    @CborLabel(6)
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant? = null,
    @CborLabel(7)
    @SerialName("jti")
    @ByteString
    val cwtId: ByteArray? = null,
    @CborLabel(10)
    @SerialName("Nonce")
    @ByteString
    val nonce: ByteArray? = null,
) {

    fun serialize() = cborSerializer.encodeToByteArray(this)

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
        fun deserialize(it: ByteArray) = runCatching {
            cborSerializer.decodeFromByteArray<CborWebToken>(it)
        }.wrap()
    }
}