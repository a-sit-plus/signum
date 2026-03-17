package at.asitplus.signum.indispensable.integrity

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.internals.ServiceLoader

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

    fun verify(data: SignatureInput, sig: CryptoSignature): KmmResult<Success>
    fun verify(data: ByteArray, sig: CryptoSignature) = verify(SignatureInput(data), sig)
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

fun SignatureAlgorithm.verifierFor(key: CryptoPublicKey): KmmResult<SignatureVerifier> = catching {
    ServiceLoader.load<SignatureVerifierProvider>().also {
        if (it.none()) throw UnsupportedCryptoException("No signature verification providers are loaded")
    }.firstNotNullOfOrNull {
        it.verifierFor(this@verifierFor, key)
    } ?: throw UnsupportedCryptoException("No loaded signature verification provider supports ${this@verifierFor} verification.")
}

fun SpecializedSignatureAlgorithm.verifierFor(key: CryptoPublicKey) = this.algorithm.verifierFor(key)
