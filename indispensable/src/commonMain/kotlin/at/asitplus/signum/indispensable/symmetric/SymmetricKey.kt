package at.asitplus.signum.indispensable.symmetric

import at.asitplus.signum.HazardousMaterials

/**
 * Symmetric encryption key. Can only be used for the specified [algorithm].
 */
sealed class SymmetricKey<A : AECapability, I : Nonce>(
    val algorithm: SymmetricEncryptionAlgorithm<A, I>,
    val secretKey: ByteArray
) {

    /**
     * Self-Contained encryption key, i.e. a single byte array is sufficient
     */
    class Integrated<A : AECapability, I : Nonce>
    @HazardousMaterials("Does not check whether key size matched algorithm! Useful for testing, but not production!")
    /**
     * Do not invoke directly! use Supreme's `SymmetricEncryptionAlgorithm.randomKey()` and `SymmetricEncryptionAlgorithm.encryptionKeyFrom(bytes)`
     * This constructor does not check for matching key sizes to allow for testing error cases!
     */
    constructor(algorithm: SymmetricEncryptionAlgorithm<A, I>, secretKey: ByteArray) :
        SymmetricKey<A, I>(algorithm, secretKey)

    /**
     * Encryption key with dedicated MAC key. Used for non-authenticated ciphers that use an external MAC function to
     * bolt-on AEAD capabilities, such as [SymmetricEncryptionAlgorithm.AES.GCM]
     * [dedicatedMacKey] defaults to [secretKey]
     */
    class WithDedicatedMac<I : Nonce>
    @HazardousMaterials("Does not check whether key size matched algorithm! Useful for testing, but not production!")
    /**
     * Do not invoke directly! use Supreme's `SymmetricEncryptionAlgorithm.randomKey()` and `SymmetricEncryptionAlgorithm.encryptionKeyFrom(bytes)`
     * This constructor does not check for matching key sizes to allow for testing error cases!
     */
    constructor(
        algorithm: SymmetricEncryptionAlgorithm<AECapability.Authenticated.WithDedicatedMac<*, *>, I>,
        secretKey: ByteArray,
        val dedicatedMacKey: ByteArray = secretKey
    ) : SymmetricKey<AECapability.Authenticated.WithDedicatedMac<*, *>, I>(
        algorithm,
        secretKey
    )
}