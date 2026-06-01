package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlNoPaddingSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 * General JSON JWE serialization.
 *
 * A general JWE carries one encrypted content value and one or more [RecipientElement]s.
 */
@ConsistentCopyVisibility
@Serializable
data class JweGeneral internal constructor(
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.PROTECTED)
    val plainProtectedHeader: ByteArray? = null,
    @SerialName(SerialNames.UNPROTECTED)
    val sharedUnprotectedHeader: JweHeader.Part? = null,
    @SerialName(SerialNames.RECIPIENTS)
    val recipientElements: List<RecipientElement>,
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.AAD)
    val additionalAuthenticatedData: ByteArray? = null,
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.INITIALIZATION_VECTOR)
    val initializationVector: ByteArray? = null,
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.CIPHERTEXT)
    val ciphertext: ByteArray,
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.AUTHENTICATION_TAG)
    val authenticationTag: ByteArray? = null,
) : JWE() {

    init {
        require(recipientElements.isNotEmpty()) { "At least one recipient is required" }
        JweProtectedHeaderSerializer.requireAbsentIfEmpty(plainProtectedHeader)
        requireAbsentIfEmpty(sharedUnprotectedHeader, SerialNames.UNPROTECTED)
        requireAbsentIfEmpty(additionalAuthenticatedData, SerialNames.AAD)
        requireAbsentIfEmpty(initializationVector, SerialNames.INITIALIZATION_VECTOR)
        requireAbsentIfEmpty(authenticationTag, SerialNames.AUTHENTICATION_TAG)
    }

    @Transient
    val jweHeaders: List<JweHeader> = recipientElements.map {
        JweHeader.fromParts(
            plainProtectedHeader,
            sharedUnprotectedHeader,
            it.unprotectedHeader,
        )
    }

    @Transient
    val additionalAuthenticatedDataInput: ByteArray =
        getAdditionalAuthenticatedData(plainProtectedHeader, additionalAuthenticatedData)

    /**
     * Returns a new [JweGeneral] with one additional recipient over the same encrypted content.
     */
    fun appendRecipient(jweFlattened: JweFlattened): JweGeneral {
        require(hasSameSharedContentAs(jweFlattened)) {
            "Additional encrypted JWE content must match existing content"
        }

        return copy(
            recipientElements = recipientElements + RecipientElement(
                unprotectedHeader = jweFlattened.recipientUnprotectedHeader,
                encryptedKey = jweFlattened.encryptedKey,
            )
        )
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JweGeneral

        if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
        if (sharedUnprotectedHeader != other.sharedUnprotectedHeader) return false
        if (recipientElements != other.recipientElements) return false
        if (!additionalAuthenticatedData.contentEquals(other.additionalAuthenticatedData)) return false
        if (!initializationVector.contentEquals(other.initializationVector)) return false
        if (!ciphertext.contentEquals(other.ciphertext)) return false
        if (!authenticationTag.contentEquals(other.authenticationTag)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = plainProtectedHeader?.contentHashCode() ?: 0
        result = 31 * result + (sharedUnprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + recipientElements.hashCode()
        result = 31 * result + (additionalAuthenticatedData?.contentHashCode() ?: 0)
        result = 31 * result + (initializationVector?.contentHashCode() ?: 0)
        result = 31 * result + ciphertext.contentHashCode()
        result = 31 * result + (authenticationTag?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        operator fun invoke(jweFlattened: List<JweFlattened>): JweGeneral = jweFlattened.toJweGeneral()

        /**
         * Creates a general JWE from header fragments and immediately encrypts [payload] for each recipient.
         *
         * Only [protectedHeader] is integrity-protected by JWE authenticated data. [encryptor] receives the protected
         * fragment separately from the merged shared and current recipient unprotected fragments.
         */
        suspend operator fun <P> invoke(
            protectedHeader: JweHeader.Part?,
            payload: P,
            sharedUnprotectedHeader: JweHeader.Part? = null,
            recipientUnprotectedHeaders: List<JweHeader.Part?> = listOf(null),
            additionalAuthenticatedData: ByteArray? = null,
            encryptor: (
                protectedHeaderPart: JweHeader.Part?,
                unprotectedHeaderPart: JweHeader.Part?,
                payload: P,
            ) -> EncryptionOutput,
        ): JweGeneral =
            recipientUnprotectedHeaders.map { recipientUnprotectedHeader ->
                JweFlattened(
                    protectedHeader = protectedHeader,
                    payload = payload,
                    sharedUnprotectedHeader = sharedUnprotectedHeader,
                    recipientUnprotectedHeader = recipientUnprotectedHeader,
                    additionalAuthenticatedData = additionalAuthenticatedData,
                    encryptor = encryptor,
                )
            }.toJweGeneral()
    }
}

val JweGeneral.protectedHeader: JweHeader.Part?
    get() = plainProtectedHeader?.let(JweProtectedHeaderSerializer::decodeFromByteArray)

/**
 * Expands general JSON JWE representation into one flattened JWE per recipient.
 */
fun JweGeneral.toJweFlattened(): List<JweFlattened> =
    recipientElements.map {
        JweFlattened(
            plainProtectedHeader = plainProtectedHeader,
            sharedUnprotectedHeader = sharedUnprotectedHeader,
            recipientUnprotectedHeader = it.unprotectedHeader,
            encryptedKey = it.encryptedKey,
            additionalAuthenticatedData = additionalAuthenticatedData,
            initializationVector = initializationVector,
            ciphertext = ciphertext,
            authenticationTag = authenticationTag,
        )
    }

private fun JweGeneral.hasSameSharedContentAs(other: JweFlattened): Boolean =
    plainProtectedHeader.contentEquals(other.plainProtectedHeader) &&
            sharedUnprotectedHeader == other.sharedUnprotectedHeader &&
            additionalAuthenticatedData.contentEquals(other.additionalAuthenticatedData) &&
            initializationVector.contentEquals(other.initializationVector) &&
            ciphertext.contentEquals(other.ciphertext) &&
            authenticationTag.contentEquals(other.authenticationTag)
