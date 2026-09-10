package at.asitplus.signum.supreme.sign

import at.asitplus.signum.dsl.JCAProviderRef
import at.asitplus.signum.dsl.VerifierConfiguration
import at.asitplus.signum.dsl.jvm
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureInput
import at.asitplus.signum.indispensable.sign.SignatureVerifier
import at.asitplus.signum.indispensable.sign.SignatureVerifierProvider
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.signum.indispensable.sign.RsaPublicKey
import java.security.Signature

abstract class SupremeJVMVerifier(algorithm: SignatureAlgorithm, key: CryptoPublicKey, protected val provider: JCAProviderRef) : SignatureVerifier {
    private val jcaPublicKey = key.toJcaPublicKey()
    // fail fast
    init { algorithm.getJCASignatureInstance(provider).apply { initVerify(jcaPublicKey) } }
    private fun verifyWith(jcaSig: Signature, data: Sequence<ByteArray>, sig: ByteArray): Boolean {
        data.forEach(jcaSig::update)
        return jcaSig.verify(sig)
    }
    override suspend fun verify(data: SignatureInput, sig: CryptoSignature): SignatureVerifier.Success {
        val success = when {
            (data.format == null) ->
                signatureAlgorithm.getJCASignatureInstance(provider)
                    .apply { initVerify(jcaPublicKey) }
                    .let { verifyWith(it, data.data, sig.jcaSignatureBytes) }
            (data.format == signatureAlgorithm.preHashedSignatureFormat) ->
                signatureAlgorithm.getJCASignatureInstancePreHashed(provider)
                    .apply { initVerify(jcaPublicKey) }
                    .let { verifyWith(it, data.data, sig.jcaSignatureBytes) }
            else ->
                throw IllegalArgumentException("Pre-hashed data (format=${data.format}) is incompatible with $signatureAlgorithm")
        }
        if (success)
            return SignatureVerifier.Success
        else
            throw InvalidSignature("Signature is cryptographically invalid")
    }

    class Ecdsa(override val signatureAlgorithm: EcdsaAlgorithm, override val publicKey: EcdsaPublicKey, provider: JCAProviderRef)
        : SupremeJVMVerifier(signatureAlgorithm, publicKey, provider), at.asitplus.signum.indispensable.sign.EcdsaVerifier

    class Rsa(override val signatureAlgorithm: RsaAlgorithm, override val publicKey: RsaPublicKey, provider: JCAProviderRef)
        : SupremeJVMVerifier(signatureAlgorithm, publicKey, provider), at.asitplus.signum.indispensable.sign.RsaVerifier
}

object SupremeJVMVerifierProvider : SignatureVerifierProvider {
    override fun verifierFor(algorithm: SignatureAlgorithm, key: CryptoPublicKey, config: VerifierConfiguration) =
        when (algorithm) {
            is EcdsaAlgorithm -> {
                require(key is EcdsaPublicKey)
                    { "Cannot instantiate ECDSA ($algorithm) verifier using non-ECDSA public key $key" }
                SupremeJVMVerifier.Ecdsa(algorithm, key, config.jvm.v.provider)
            }
            is RsaAlgorithm -> {
                require(key is RsaPublicKey)
                    { "Cannot instantiate RSA ($algorithm) verifier using non-RSA public key $key" }
                SupremeJVMVerifier.Rsa(algorithm, key, config.jvm.v.provider)
            }
            else -> null
        }
}
