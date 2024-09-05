package at.asitplus.signum.indispensable

@RequiresOptIn("This is dangerous cryptography, which is easy to misuse. Ensure you know what you are doing, or use a less dangerous variant.")
annotation class DangerousCryptography

sealed interface AESModes {
    /** Plain block-by-block encryption. Ignores nonce. Entirely unsuitable for real-world use. */
    @DangerousCryptography data object ECB: AESModes

    /** Modes for Authentication Encryption with Additional Data. Ciphertext is tamper-resistant,
     * and authenticity of additional context data can be assured without encrypting it. */
    sealed interface AEAD: AESModes
    /** Basic AEAD mode. Marked dangerous because any nonce reuse will compromise the private key.
     * Consider [GCM_SIV] or [SIV] instead. */
    @DangerousCryptography data object GCM: AEAD
    /** Variant of [GCM] that is nonce reuse resistant. */
    //data object GCM_SIV: AEAD

}
sealed interface SymmetricEncryptionAlgorithm {
    sealed interface AEAD: SymmetricEncryptionAlgorithm
    data class AES_LEGACY internal constructor(val mode: AESModes): SymmetricEncryptionAlgorithm
    data class AES_AEAD internal constructor(val mode: AESModes.AEAD): SymmetricEncryptionAlgorithm, AEAD
    fun AES(mode: AESModes) = when (mode) {
        is AESModes.AEAD -> AES_AEAD(mode)
        else -> AES_LEGACY(mode)
    }
}