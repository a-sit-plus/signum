package at.asitplus.signum.indispensable

/**
 * Symmetric Encryption key
 */
sealed class SymmetricKey<A : CipherKind, I : IV>(
    val algorithm: SymmetricEncryptionAlgorithm<A, I>,
    val secretKey: ByteArray
) {

    /**
     * Self-Contained encryption key, i.e. a single byte array is sufficient
     */
    class Integrated<A : CipherKind, I : IV>(algorithm: SymmetricEncryptionAlgorithm<A, I>, secretKey: ByteArray) :
        SymmetricKey<A, I>(algorithm, secretKey)

    /**
     * Encryption key with dedicated MAC key.
     * [dedicatedMacKey] defaults to [secretKey]
     */
    class WithDedicatedMac<I : IV>(
        algorithm: SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, *>, I>,
        secretKey: ByteArray,
        val dedicatedMacKey: ByteArray = secretKey
    ) : SymmetricKey<CipherKind.Authenticated.WithDedicatedMac<*, *>, I>(
        algorithm,
        secretKey
    )
}