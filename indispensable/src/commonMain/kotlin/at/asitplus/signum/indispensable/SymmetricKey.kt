package at.asitplus.signum.indispensable

/**
 * Symmetric Encryption key
 */
sealed class SymmetricKey<A : AuthTrait>(val algorithm: SymmetricEncryptionAlgorithm<A>, val secretKey: ByteArray) {

    /**
     * Self-Contained encryption key, i.e. a single byte array is sufficient
     */
    class Integrated<A : AuthTrait>(algorithm: SymmetricEncryptionAlgorithm<A>, secretKey: ByteArray) :
        SymmetricKey<A>(algorithm, secretKey)

    /**
     * Encryption key with dedicated MAC key
     */
    class WithDedicatedMac(
        algorithm: SymmetricEncryptionAlgorithm.WithDedicatedMac,
        secretKey: ByteArray,
        val dedicatedMacKey: ByteArray
    ) : SymmetricKey<AuthTrait.Authenticated>(algorithm, secretKey)
}