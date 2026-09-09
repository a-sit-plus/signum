@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.signum.supreme.sign

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.internals.*
import at.asitplus.signum.dsl.VerifierConfiguration
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureInput
import at.asitplus.signum.indispensable.sign.SignatureVerifier
import at.asitplus.signum.indispensable.sign.SignatureVerifierProvider
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.signum.indispensable.sign.RsaPublicKey
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSOSStatusErrorDomain
import platform.Security.SecKeyVerifySignature
import platform.Security.errSecVerifyFailed

object SupremeCCVerifierProvider : SignatureVerifierProvider {
    override fun verifierFor(algorithm: SignatureAlgorithm, key: CryptoPublicKey, config: VerifierConfiguration) = when(algorithm) {
        is EcdsaAlgorithm -> {
            require (key is EcdsaPublicKey)
                { "Attempt to create ECDSA ($algorithm) verifier using non-ECDSA public key ($key)"}
            when (algorithm.digest) {
                null -> SupremeCCVerifier.EcdsaPreHashed(algorithm, key)
                else -> SupremeCCVerifier.Ecdsa(algorithm, key)
            }
        }
        is RsaAlgorithm -> {
            require (key is RsaPublicKey)
                { "Attempt to create RSA ($algorithm) verifier using non-RSA public key ($key)" }
            SupremeCCVerifier.Rsa(algorithm, key)
        }
        else -> null
    }
}

abstract class SupremeCCVerifier: SignatureVerifier {
    override suspend fun verify(data: SignatureInput, sig: CryptoSignature): SignatureVerifier.Success {
        val key = publicKey.toSecKey()
        val (algorithm, format) = signatureAlgorithm.suitableSecKeyAlgAndFormat
        val inputData = data.convertTo(format).collapsed().data.single()
        try {
            /** inner takeIf ensures that only true returns, false will throw. see [corecall] */
            val result = corecall {
                SecKeyVerifySignature(key.value, algorithm,
                    inputData.toNSData().giveToCF(), sig.secKeySignature.toNSData().giveToCF(), error).takeIf { it }
            }
            if (result == true) return SignatureVerifier.Success
            else error("unreachable")
        } catch (x: CoreFoundationException) {
            if ((x.nsError.domain == NSOSStatusErrorDomain) && (x.nsError.code == errSecVerifyFailed.toLong()))
                throw InvalidSignature("Signature failed to verify", x)
            throw x
        }
    }

    class Ecdsa(override val signatureAlgorithm: EcdsaAlgorithm, override val publicKey: EcdsaPublicKey)
        : SupremeCCVerifier(), at.asitplus.signum.indispensable.sign.EcdsaVerifier
    {
        init { require(signatureAlgorithm.digest != null) }
    }

    class EcdsaPreHashed(override val signatureAlgorithm: EcdsaAlgorithm, override val publicKey: EcdsaPublicKey)
        : at.asitplus.signum.indispensable.sign.EcdsaVerifier
    {
        init { require(signatureAlgorithm.digest == null) }
        private val targetDigest = publicKey.curve.nativeDigest
        private val inner = Ecdsa(EcdsaAlgorithm(targetDigest, null), publicKey)

        override suspend fun verify(data: SignatureInput, sig: CryptoSignature): SignatureVerifier.Success {
            @OptIn(HazardousMaterials::class)
            val fakeInput = SignatureInput.unsafeCreate(
                data.asECDSABigInteger(targetDigest.outputLength).toByteArray().ensureSize(targetDigest.outputLength.bytes),
                targetDigest
            )
            return inner.verify(fakeInput, sig)
        }
    }

    class Rsa(override val signatureAlgorithm: RsaAlgorithm, override val publicKey: RsaPublicKey)
        : SupremeCCVerifier(), at.asitplus.signum.indispensable.sign.RsaVerifier
}
