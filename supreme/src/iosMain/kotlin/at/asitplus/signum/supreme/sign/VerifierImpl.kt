@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.internals.*
import at.asitplus.signum.dsl.VerifierConfiguration
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.integrity.SignatureInput
import at.asitplus.signum.indispensable.integrity.SignatureVerifier
import at.asitplus.signum.indispensable.integrity.SignatureVerifierProvider
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSOSStatusErrorDomain
import platform.Security.SecKeyVerifySignature
import platform.Security.errSecVerifyFailed

object SupremeCCVerifierProvider : SignatureVerifierProvider {
    override fun verifierFor(algorithm: SignatureAlgorithm, key: CryptoPublicKey, config: VerifierConfiguration) = when(algorithm) {
        is ECDSAAlgorithm -> {
            require (key is ECDSAPublicKey)
                { "Attempt to create ECDSA ($algorithm) verifier using non-ECDSA public key ($key)"}
            when (algorithm.digest) {
                null -> SupremeCCVerifier.ECDSAPreHashed(algorithm, key)
                else -> SupremeCCVerifier.ECDSA(algorithm, key)
            }
        }
        is RSAAlgorithm -> {
            require (key is RSAPublicKey)
                { "Attempt to create RSA ($algorithm) verifier using non-RSA public key ($key)" }
            SupremeCCVerifier.RSA(algorithm, key)
        }
        else -> null
    }
}

abstract class SupremeCCVerifier: SignatureVerifier {
    override suspend fun verify(data: SignatureInput, sig: CryptoSignature) = catching {
        val key = publicKey.toSecKey().getOrThrow()
        val inputData = data.convertTo(signatureAlgorithm.preHashedSignatureFormat).getOrThrow().data.single()
        try {
            /** inner takeIf ensures that only true returns, false will throw. see [corecall] */
            val _ = corecall {
                SecKeyVerifySignature(key.value, signatureAlgorithm.secKeyAlgorithmPreHashed,
                    inputData.toNSData().let(::giveToCF), sig.iosEncoded.toNSData().let(::giveToCF), error).takeIf { it }
            }
        } catch (x: CoreFoundationException) {
            if ((x.nsError.domain == NSOSStatusErrorDomain) && (x.nsError.code == errSecVerifyFailed.toLong()))
                throw InvalidSignature("Signature failed to verify", x)
            throw x
        }
        SignatureVerifier.Success
    }

    class ECDSA(override val signatureAlgorithm: ECDSAAlgorithm, override val publicKey: ECDSAPublicKey)
        : SupremeCCVerifier(), SignatureVerifier.ECDSA
    {
        init { require(signatureAlgorithm.digest != null) }
    }

    class ECDSAPreHashed(override val signatureAlgorithm: ECDSAAlgorithm, override val publicKey: ECDSAPublicKey)
        : SignatureVerifier.ECDSA
    {
        init { require(signatureAlgorithm.digest == null) }
        private val targetDigest = publicKey.curve.nativeDigest
        private val inner = ECDSA(ECDSAAlgorithm(targetDigest, null), publicKey)

        override suspend fun verify(data: SignatureInput, sig: CryptoSignature) = catching {
            check(publicKey.curve.scalarLength == targetDigest.outputLength)
            SignatureInput.unsafeCreate(
                data.asECDSABigInteger(targetDigest.outputLength).toByteArray().ensureSize(targetDigest.outputLength.bytes),
                targetDigest
            )
        }.transform { inner.verify(it, sig) }
    }

    class RSA(override val signatureAlgorithm: RSAAlgorithm, override val publicKey: RSAPublicKey)
        : SupremeCCVerifier(), SignatureVerifier.RSA
}
