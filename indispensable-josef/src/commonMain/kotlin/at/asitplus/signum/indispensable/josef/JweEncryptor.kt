package at.asitplus.signum.indispensable.josef


fun interface JweEncryptor<P, A> {
    suspend fun invoke(encryptionInput: EncryptionInput<P,A>): EncryptionOutput

    data class EncryptionInput<P, A>(
        val protectedHeader: JweHeader.Part?,
        val unprotectedHeader: JweHeader.Part?,
        val payload: P,
        val aad: A?
    )

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