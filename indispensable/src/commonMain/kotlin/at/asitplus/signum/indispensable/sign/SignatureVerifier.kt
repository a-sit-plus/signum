package at.asitplus.signum.indispensable.sign

import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.dsl.DSL
import at.asitplus.signum.dsl.DSLConfigureFn
import at.asitplus.signum.dsl.VerifierConfiguration
import at.asitplus.signum.indispensable.AbstractSignature
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.CertificationRequest
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.toAsn1
import kotlinx.serialization.encodeToByteArray

interface SignatureVerifier {
    val signatureAlgorithm: SignatureAlgorithm
    val publicKey: CryptoPublicKey

    @Deprecated(message = "Concrete algorithm typess migrated out of SignatureVerifier as part of providerization",
        replaceWith = ReplaceWith("EcdsaVerifier"))
    typealias ECDSA = EcdsaVerifier

    @Deprecated(message = "Concrete algorithm typess migrated out of SignatureVerifier as part of providerization",
        replaceWith = ReplaceWith("RsaVerifier"))
    typealias RSA = RsaVerifier

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
suspend fun SignatureVerifier.verify(data: SignatureInput, sig: AbstractSignature) =
    verify(data, sig.withSignatureAlgorithm(signatureAlgorithm))
@IgnorableReturnValue
suspend fun SignatureVerifier.verify(data: ByteArray, sig: AbstractSignature) =
    verify(SignatureInput(data), sig)
@IgnorableReturnValue
suspend fun SignatureVerifier.verify(data: Sequence<ByteArray>, sig: AbstractSignature) =
    verify(SignatureInput(data), sig)

@IgnorableReturnValue
suspend fun SignatureVerifier.verify(input: TbsCertificate, signature: CryptoSignature) =
    verify(Signum.Der.encodeToByteArray(input), signature)

@IgnorableReturnValue
suspend fun SignatureVerifier.verify(input: Certificate): SignatureVerifier.Success {
    require(this.signatureAlgorithm == input.signatureAlgorithm)
    return verify(input.tbsCertificate.toAsn1.DER(), input.signature)
}

fun CertificationRequest.verifier() =
    this.signatureAlgorithm.verifierFor(this.tbsCsr.publicKey)

suspend fun CertificationRequest.verify() =
    this.verifier().verify(this)

@IgnorableReturnValue
/** Verify the proof of possession of the contained public key. Asserts that [this] matches the encoded [CertificationRequest.publicKey].
 * @see SignatureVerifier.verify */
suspend fun SignatureVerifier.verify(input: CertificationRequest): SignatureVerifier.Success {
    require(this.signatureAlgorithm == input.signatureAlgorithm)
    require(this.publicKey == input.publicKey)
    return verify(input.tbsCsr.toAsn1.DER(), input.signature)
}

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

fun TbsCertificate.verifier(configure: DSLConfigureFn<VerifierConfiguration> = null) =
    this.signatureAlgorithm.verifierFor(this.publicKey, configure)

fun Certificate.verifier(configure: DSLConfigureFn<VerifierConfiguration> = null) =
    tbsCertificate.verifier(configure)
