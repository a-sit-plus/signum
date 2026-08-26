package at.asitplus.signum.supreme.sign

import at.asitplus.signum.dsl.JCAProviderRef
import at.asitplus.signum.dsl.VerifierConfiguration
import at.asitplus.signum.dsl.jvm
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.integrity.SignatureInput
import at.asitplus.signum.indispensable.integrity.SignatureVerifier
import at.asitplus.signum.indispensable.integrity.SignatureVerifierProvider
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import java.security.Signature

abstract class SupremeJVMVerifier(algorithm: SignatureAlgorithm, key: CryptoPublicKey, protected val provider: JCAProviderRef) : SignatureVerifier {
    private val instance = algorithm.getJCASignatureInstance(provider).apply { initVerify(key.toJcaPublicKey()) }
    private fun verifyWith(jcaSig: Signature, data: Sequence<ByteArray>, sig: ByteArray): Boolean {
        data.forEach(jcaSig::update)
        return jcaSig.verify(sig)
    }
    override suspend fun verify(data: SignatureInput, sig: CryptoSignature): SignatureVerifier.Success {
        val success = when {
            (data.format == null) -> verifyWith(instance, data.data, sig.jcaSignatureBytes)
            (data.format == signatureAlgorithm.preHashedSignatureFormat) ->
                signatureAlgorithm.getJCASignatureInstancePreHashed(provider)
                    .apply { initVerify(publicKey.toJcaPublicKey()) }
                    .let { verifyWith(it, data.data, sig.jcaSignatureBytes) }
            else -> throw IllegalArgumentException("Pre-hashed data (format=${data.format}) is incompatible with $signatureAlgorithm")
        }
        if (success)
            return SignatureVerifier.Success
        else
            throw InvalidSignature("Signature is cryptographically invalid")
    }

    class ECDSA(override val signatureAlgorithm: ECDSAAlgorithm, override val publicKey: ECDSAPublicKey, provider: JCAProviderRef)
        : SupremeJVMVerifier(signatureAlgorithm, publicKey, provider), SignatureVerifier.ECDSA

    class RSA(override val signatureAlgorithm: RSAAlgorithm, override val publicKey: RSAPublicKey, provider: JCAProviderRef)
        : SupremeJVMVerifier(signatureAlgorithm, publicKey, provider), SignatureVerifier.RSA
}

object SupremeJVMVerifierProvider : SignatureVerifierProvider {
    override fun verifierFor(algorithm: SignatureAlgorithm, key: CryptoPublicKey, config: VerifierConfiguration) =
        when (algorithm) {
            is ECDSAAlgorithm -> {
                require(key is ECDSAPublicKey)
                    { "Cannot instantiate ECDSA ($algorithm) verifier using non-ECDSA public key $key" }
                SupremeJVMVerifier.ECDSA(algorithm, key, config.jvm.v.provider)
            }
            is RSAAlgorithm -> {
                require(key is RSAPublicKey)
                    { "Cannot instantiate RSA ($algorithm) verifier using non-RSA public key $key" }
                SupremeJVMVerifier.RSA(algorithm, key, config.jvm.v.provider)
            }
            else -> null
        }
}
