package at.asitplus.signum.indispensable.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.awesn1.encoding.bitLength
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.misc.BitLength
import org.kotlincrypto.random.CryptoRand
import kotlin.jvm.JvmName

private inline fun randomBytes(n: Int, random: CryptoRand = CryptoRand.Default): ByteArray =
    ByteArray(n).also {   random.nextBytes(it)}

/**
 * Generates a fresh random key for this algorithm.
 */
@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE", "UNCHECKED_CAST")
@kotlin.internal.LowPriorityInOverloadResolution
suspend fun <A : AuthCapability, I : NonceTrait> SymmetricEncryptionAlgorithm<A, I>.randomKey() =
    @OptIn(HazardousMaterials::class) randomKey(CryptoRand.Default)
/**
 * Generates a fresh random key for this algorithm.
 */
@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE", "UNCHECKED_CAST")
@kotlin.internal.LowPriorityInOverloadResolution
@HazardousMaterials("The default randomness source is cryptographically secure. If you override it, make sure you know what you are doing (such as for deterministic tests).")
suspend fun <E : SymmetricEncryptionAlgorithm<*, *>> E.randomKey(
    random: CryptoRand
): SymmetricKey<E> {
    val bytes = randomBytes(keySize.bytes.toInt(), random)
    return (if (hasDedicatedMac()) keyFrom(bytes, randomBytes(preferredMacKeyLength.bytes.toInt(), random))
    else keyFrom(bytes))
}


/**
 * Generates a fresh random key for this algorithm.
 * [macKeyLength] can be specified to override [preferredMacKeyLength].
 */
@JvmName("randomKeyAndMacKey")
suspend fun <E : SymmetricEncryptionAlgorithm.EncryptThenMAC<*>> E.randomKey(
    macKeyLength: BitLength
) = @OptIn(HazardousMaterials::class) randomKey(macKeyLength, CryptoRand.Default)
/**
 * Generates a fresh random key for this algorithm.
 * [macKeyLength] can be specified to override [preferredMacKeyLength].
 */
@JvmName("randomKeyAndMacKey")
@HazardousMaterials("The default randomness source is cryptographically secure. If you override it, make sure you know what you are doing (such as for deterministic tests).")
suspend fun <E : SymmetricEncryptionAlgorithm.EncryptThenMAC<*>> E.randomKey(
    macKeyLength: BitLength,
    random: CryptoRand
): SymmetricKey<E> =
    keyFrom(
        randomBytes(keySize.bytes.toInt(), random),
        randomBytes(macKeyLength.bytes.toInt(), random)
    )


/**
 * Generates a new random nonce matching the Nonce size of this algorithm.
 * You typically don't want to use this, but have your nonces auto-generated during the encryption process
 */
@HazardousMaterials("Don't explicitly generate nonces!")
fun SymmetricEncryptionAlgorithm<*, NonceTrait.Required>.randomNonce(): ByteArray =
    @OptIn(HazardousMaterials::class) randomNonce(CryptoRand.Default)

/**
 * Generates a new random nonce matching the Nonce size of this algorithm.
 * You typically don't want to use this, but have your nonces auto-generated during the encryption process
 */
@HazardousMaterials("Don't explicitly generate nonces!")
@HazardousMaterials("The default randomness source is cryptographically secure. If you override it, make sure you know what you are doing (such as for deterministic tests).")
fun SymmetricEncryptionAlgorithm<*, NonceTrait.Required>.randomNonce(random: CryptoRand): ByteArray =
    randomBytes((nonceSize.bytes).toInt(), random)


@OptIn(HazardousMaterials::class)
private fun SymmetricEncryptionAlgorithm<*, *>.checkKeySize(
    bytes: ByteArray,
) =
    require(bytes.size == this.keySize.bytes.toInt()) { "Invalid key size: ${bytes.size * 8}. Required: keySize=${bytes.size.bitLength}" }

/**
 * Creates a [SymmetricKey] from the specified [secretKey].
 * @throws IllegalArgumentException if the provided bytes don't match [SymmetricEncryptionAlgorithm.keySize]
 */
@JvmName("fixedKeyIntegrated")
@Suppress("UNCHECKED_CAST")
@Throws(Throwable::class)
fun <E : SymmetricEncryptionAlgorithm.Integrated<*>> E.keyFrom(
    secretKey: ByteArray
): SymmetricKey<E> {
    checkKeySize(secretKey)
    return SymmetricKey.Integrated(this, secretKey)
}

/**
 * Creates a [SymmetricKey] from the specified [encryptionKey] and [macKey].
 * @throws IllegalArgumentException if the provided bytes don't match [SymmetricEncryptionAlgorithm.keySize] or the specified [macKey] is empty.
 */
@OptIn(HazardousMaterials::class)
@JvmName("fixedKeyDedicatedMacKey")
@Suppress("UNCHECKED_CAST")
@Throws(Throwable::class)
fun <E : SymmetricEncryptionAlgorithm.EncryptThenMAC<*>> E.keyFrom(
    encryptionKey: ByteArray,
    macKey: ByteArray
): SymmetricKey<E> {
    checkKeySize(encryptionKey)
    require(macKey.isNotEmpty()) { "Dedicated MAC key is empty!" }
    return SymmetricKey.WithDedicatedMac(this, encryptionKey, macKey)
}


suspend fun SpecializedSymmetricEncryptionAlgorithm.randomKey() =
    @OptIn(HazardousMaterials::class) randomKey(CryptoRand.Default)

@HazardousMaterials("The default randomness source is cryptographically secure. If you override it, make sure you know what you are doing (such as for deterministic tests).")
suspend fun SpecializedSymmetricEncryptionAlgorithm.randomKey(random: CryptoRand) =
    algorithm.randomKey(random)
