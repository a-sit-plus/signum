package at.asitplus.signum.indispensable.symmetric

import at.asitplus.signum.HazardousMaterials

sealed interface KeyType{
    object Integrated: KeyType
    object WithDedicatedMacKey: KeyType
}
/**
 * Symmetric encryption key. Can only be used for the specified [algorithm].
 */
sealed class SymmetricKey<A : AuthType<K>, I : Nonce, K: KeyType>(
    val algorithm: SymmetricEncryptionAlgorithm<A, I,K>,
    val secretKey: ByteArray
) {

    /**
     * Self-Contained encryption key, i.e. a single byte array is sufficient
     */
    class Integrated<A : AuthType<KeyType.Integrated>, I : Nonce>
    @HazardousMaterials("Does not check whether key size matched algorithm! Useful for testing, but not production!")
    /**
     * Do not invoke directly! use Supreme's `SymmetricEncryptionAlgorithm.randomKey()` and `SymmetricEncryptionAlgorithm.encryptionKeyFrom(bytes)`
     * This constructor does not check for matching key sizes to allow for testing error cases!
     */
    constructor(algorithm: SymmetricEncryptionAlgorithm<A, I, KeyType.Integrated>, secretKey: ByteArray) :
        SymmetricKey<A, I,KeyType.Integrated>(algorithm, secretKey)

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
        algorithm: SymmetricEncryptionAlgorithm<AuthType.Authenticated.WithDedicatedMac<*, I>, I, KeyType.WithDedicatedMacKey>,
        secretKey: ByteArray,
        val dedicatedMacKey: ByteArray
    ) : SymmetricKey<AuthType.Authenticated.WithDedicatedMac<*, *>, I, KeyType.WithDedicatedMacKey>(
        algorithm,
        secretKey
    )
}
