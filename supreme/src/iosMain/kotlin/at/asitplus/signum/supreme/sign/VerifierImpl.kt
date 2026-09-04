@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.internals.*
import at.asitplus.signum.dsl.VerifierConfiguration
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureInput
import at.asitplus.signum.indispensable.sign.SignatureVerifier
import at.asitplus.signum.indispensable.sign.SignatureVerifierProvider
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

        override suspend fun verify(data: SignatureInput, sig: CryptoSignature): SignatureVerifier.Success {
            check(publicKey.curve.scalarLength == targetDigest.outputLength)
            val fakeInput = SignatureInput.unsafeCreate(
                data.asECDSABigInteger(targetDigest.outputLength).toByteArray().ensureSize(targetDigest.outputLength.bytes),
                targetDigest
            )
            return inner.verify(fakeInput, sig)
        }
    }

    class RSA(override val signatureAlgorithm: RSAAlgorithm, override val publicKey: RSAPublicKey)
        : SupremeCCVerifier(), SignatureVerifier.RSA
}
