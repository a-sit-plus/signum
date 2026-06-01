package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlNoPaddingSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * One recipient entry of general JSON JWE serialization.
 */
@ConsistentCopyVisibility
@Serializable
data class RecipientElement internal constructor(
    @SerialName(JWE.SerialNames.HEADER)
    val unprotectedHeader: JweHeader.Part? = null,
    @SerialName(JWE.SerialNames.ENCRYPTED_KEY)
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    val encryptedKey: ByteArray? = null,
) {
    init {
        requireAbsentIfEmpty(unprotectedHeader, JWE.SerialNames.HEADER)
        requireAbsentIfEmpty(encryptedKey, JWE.SerialNames.ENCRYPTED_KEY)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as RecipientElement

        if (unprotectedHeader != other.unprotectedHeader) return false
        if (!encryptedKey.contentEquals(other.encryptedKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = unprotectedHeader?.hashCode() ?: 0
        result = 31 * result + (encryptedKey?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        operator fun invoke(
            unprotectedHeader: JweHeader.Part? = null,
            encryptedKey: ByteArray? = null,
        ): RecipientElement = RecipientElement(
            unprotectedHeader = unprotectedHeader?.takeUnless { it.toJsonObject().isEmpty() },
            encryptedKey = encryptedKey.takeUnlessEmpty(),
        )
    }
}
