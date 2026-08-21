package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.ecmath.straussShamir
import at.asitplus.signum.indispensable.integrity.SignatureInput
import at.asitplus.signum.indispensable.integrity.SignatureVerifier
import at.asitplus.signum.indispensable.integrity.SignatureVerifierProvider
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.ECDSASignature
import at.asitplus.signum.dsl.DSLConfigureFn
import at.asitplus.signum.dsl.JCAProviderRef
import at.asitplus.signum.dsl.VerifierConfiguration
import at.asitplus.signum.dsl.jvm
import at.asitplus.signum.indispensable.integrity.verifierFor

class InvalidSignature(message: String, cause: Throwable? = null): Throwable(message, cause)

class KotlinECDSAVerifier
    internal constructor (override val signatureAlgorithm: ECDSAAlgorithm, override val publicKey: ECDSAPublicKey)
    : SignatureVerifier.ECDSA {
    override suspend fun verify(data: SignatureInput, sig: CryptoSignature) = catching {
        require(sig is ECDSASignature)
            { "Attempted to validate ${sig::class.simpleName} signature using EC public key" }

        val curve = publicKey.curve

        when (sig) {
            is ECDSASignature.DefiniteLength -> require(sig.scalarByteLength == curve.scalarLength.bytes)
            is ECDSASignature.IndefiniteLength -> { val _ = sig.withCurve(curve) /* validate */ }
        }
        if (!((sig.r > 0) && (sig.r < curve.order))) {
            throw InvalidSignature("r is not in [1,n-1] (r=${sig.r}, n=${curve.order})")
        }
        if (!((sig.s > 0) && (sig.s < curve.order))) {
            throw InvalidSignature("s is not in [1,n-1] (s=${sig.s}, n=${curve.order})")
        }

        val z = data.convertTo(signatureAlgorithm.digest).getOrThrow().asECDSABigInteger(curve.scalarLength)
        val sInv = sig.s.modInverse(curve.order)
        val u1 = (z * sInv).mod(curve.order)
        val u2 = (sig.r * sInv).mod(curve.order)
        val point = straussShamir(u1, curve.generator, u2, publicKey.publicPoint).run {
            tryNormalize() ?: throw InvalidSignature("(x1,y1) = additive zero") }
        if (point.x.residue.mod(curve.order) != sig.r.mod(curve.order)) {
            throw InvalidSignature("Signature is invalid: x1 != r")
        }
        return@catching SignatureVerifier.Success
    }
}

object SupremeKotlinVerifierProvider : SignatureVerifierProvider {
    override fun verifierFor(algorithm: SignatureAlgorithm, key: CryptoPublicKey, config: VerifierConfiguration): SignatureVerifier? {
        if (config.jvm.v.provider != JCAProviderRef.None) throw UnsupportedOperationException("Not substituting Kotlin verifier when specific JCA provider is requested")
        if (algorithm !is ECDSAAlgorithm) return null
        if (key !is ECDSAPublicKey)
            throw IllegalArgumentException("Non-EC public key passed to ECDSA algorithm")
        return KotlinECDSAVerifier(algorithm, key)
    }
}

@Deprecated("platform distinction is unsupported in provider system; if you want a particular instantiation, ask that provider specifically")
fun SignatureAlgorithm.platformVerifierFor
            (publicKey: CryptoPublicKey, configure: DSLConfigureFn<VerifierConfiguration> = null) =
    this.verifierFor(publicKey, configure)
