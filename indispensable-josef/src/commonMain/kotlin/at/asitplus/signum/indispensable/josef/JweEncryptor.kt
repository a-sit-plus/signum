package at.asitplus.signum.indispensable.josef


fun interface JweEncryptor {
    suspend operator fun invoke(encryptionInput: EncryptionInput): EncryptionOutput

    data class EncryptionInput(
        val protectedHeader: JweHeader.Part?,
        val sharedUnprotectedHeader: JweHeader.Part?,
        val recipientUnprotectedHeader: JweHeader.Part?,
        val payload: ByteArray,
        val additionalAuthenticatedData: ByteArray?
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as EncryptionInput

            if (protectedHeader != other.protectedHeader) return false
            if (sharedUnprotectedHeader != other.sharedUnprotectedHeader) return false
            if (recipientUnprotectedHeader != other.recipientUnprotectedHeader) return false
            if (!payload.contentEquals(other.payload)) return false
            if (!additionalAuthenticatedData.contentEquals(other.additionalAuthenticatedData)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = protectedHeader?.hashCode() ?: 0
            result = 31 * result + (sharedUnprotectedHeader?.hashCode() ?: 0)
            result = 31 * result + (recipientUnprotectedHeader?.hashCode() ?: 0)
            result = 31 * result + payload.contentHashCode()
            result = 31 * result + (additionalAuthenticatedData?.contentHashCode() ?: 0)
            return result
        }
    }

    data class EncryptionOutput(
        val iv: ByteArray? = null,
        val cipherText: ByteArray,
        val encryptedKey: ByteArray? = null,
        val authenticationTag: ByteArray? = null,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as EncryptionOutput

            if (!iv.contentEquals(other.iv)) return false
            if (!cipherText.contentEquals(other.cipherText)) return false
            if (!encryptedKey.contentEquals(other.encryptedKey)) return false
            if (!authenticationTag.contentEquals(other.authenticationTag)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = iv?.contentHashCode() ?: 0
            result = 31 * result + cipherText.contentHashCode()
            result = 31 * result + (encryptedKey?.contentHashCode() ?: 0)
            result = 31 * result + (authenticationTag?.contentHashCode() ?: 0)
            return result
        }
    }
}