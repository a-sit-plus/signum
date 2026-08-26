package at.asitplus.signum.indispensable.integrity

import at.asitplus.KmmResult
import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.dsl.DSL
import at.asitplus.signum.dsl.DSLConfigureFn
import at.asitplus.signum.dsl.VerifierConfiguration
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import at.asitplus.signum.indispensable.withSignatureAlgorithm

interface SignatureVerifier {
    val signatureAlgorithm: SignatureAlgorithm
    val publicKey: CryptoPublicKey

    interface ECDSA : SignatureVerifier {
        override val signatureAlgorithm: ECDSAAlgorithm
        override val publicKey: ECDSAPublicKey
    }

    interface RSA : SignatureVerifier {
        override val signatureAlgorithm: RSAAlgorithm
        override val publicKey: RSAPublicKey
    }

    /** Make it explicit that we only return on successful validation */
    data object Success

    /** Verify the signature. Returns on success. Throws on failure. */
    @IgnorableReturnValue
    suspend fun verify(data: SignatureInput, sig: CryptoSignature): Success
}
@IgnorableReturnValue
suspend fun SignatureVerifier.verify(data: ByteArray, sig: CryptoSignature) =
    verify(SignatureInput(data), sig)
@IgnorableReturnValue
suspend fun SignatureVerifier.verify(data: Sequence<ByteArray>, sig: CryptoSignature) =
    verify(SignatureInput(data), sig)
@IgnorableReturnValue
suspend fun SignatureVerifier.verify(data: SignatureInput, sig: DerEncodable<X509SignatureValue>) =
    verify(data, sig as? CryptoSignature ?: sig.withSignatureAlgorithm(signatureAlgorithm))
@IgnorableReturnValue
suspend fun SignatureVerifier.verify(data: ByteArray, sig: DerEncodable<X509SignatureValue>) =
    verify(SignatureInput(data), sig)
@IgnorableReturnValue
suspend fun SignatureVerifier.verify(data: Sequence<ByteArray>, sig: DerEncodable<X509SignatureValue>) =
    verify(SignatureInput(data), sig)

// @Service
interface SignatureVerifierProvider {
    /**
     * If this [algorithm] is supported by this provider, return a verifier for the given [key].
     * - If the [SignatureAlgorithm] is unsupported or unrecognized, providers should return null.
     * - If the [SignatureAlgorithm] is supported, but the provided [CryptoPublicKey] does not match it, providers should throw.
     */
    fun verifierFor(algorithm: SignatureAlgorithm, key: CryptoPublicKey, config: VerifierConfiguration): SignatureVerifier?
}

fun SignatureAlgorithm.verifierFor(key: CryptoPublicKey, configure: DSLConfigureFn<VerifierConfiguration> = null): SignatureVerifier {
    val config = DSL.resolve(::VerifierConfiguration, configure)
    return ServiceLoader.load<SignatureVerifierProvider>().get(this) { verifierFor(it, key, config) }
}

fun SpecializedSignatureAlgorithm.verifierFor(key: CryptoPublicKey) = this.algorithm.verifierFor(key)
