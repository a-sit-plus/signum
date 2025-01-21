package at.asitplus.signum.indispensable

/**
 * Symmetric Encryption key
 */
sealed class SymmetricKey<A : CipherKind, E : SymmetricEncryptionAlgorithm<A>>(
    val algorithm: E,
    val secretKey: ByteArray
) {

    /**
     * Self-Contained encryption key, i.e. a single byte array is sufficient
     */
    class Integrated<A : CipherKind>(algorithm: SymmetricEncryptionAlgorithm<A>, secretKey: ByteArray) :
        SymmetricKey<A, SymmetricEncryptionAlgorithm<A>>(algorithm, secretKey)

    /**
     * Encryption key with dedicated MAC key.
     * [dedicatedMacKey] defaults to [secretKey]
     */
    class WithDedicatedMac(
        algorithm: SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac,
        secretKey: ByteArray,
        val dedicatedMacKey: ByteArray = secretKey
    ) : SymmetricKey<CipherKind.Authenticated.WithDedicatedMac, SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac>(
        algorithm,
        secretKey
    )
}