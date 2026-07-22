package at.asitplus.signum.indispensable.integrity

import at.asitplus.KmmResult
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.ServiceLoader

interface SignatureVerifier {
    val signatureAlgorithm: SignatureAlgorithm
    val publicKey: CryptoPublicKey

    /**
     * Works around the pathological behavior of KmmResult<Unit> with .map, which would make
     * ```
     * val proxyVerify(...): KmmResult<Unit> = getVerifier().map { it.verify(...) }
     * ```
     * silently succeed (with the programmer confusing `map` and `transform`).
     */
    data object Success

    suspend fun verify(data: SignatureInput, sig: CryptoSignature): KmmResult<Success>
    suspend fun verify(data: ByteArray, sig: CryptoSignature) = verify(SignatureInput(data), sig)
}

// @Service
interface SignatureVerifierProvider {
    /**
     * If this [algorithm] is supported by this provider, return a verifier for the given [key].
     * - If the [SignatureAlgorithm] is unsupported or unrecognized, providers should return null.
     * - If the [SignatureAlgorithm] is supported, but the provided [CryptoPublicKey] does not match it, providers should throw.
     */
    fun verifierFor(algorithm: SignatureAlgorithm, key: CryptoPublicKey): SignatureVerifier?
}

fun SignatureAlgorithm.verifierFor(key: CryptoPublicKey): SignatureVerifier =
    ServiceLoader.load<SignatureVerifierProvider>().get(this) { verifierFor(it, key) }

fun SpecializedSignatureAlgorithm.verifierFor(key: CryptoPublicKey) = this.algorithm.verifierFor(key)
