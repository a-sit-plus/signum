package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.ecmath.straussShamir
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.integrity.SignatureInput
import at.asitplus.signum.indispensable.integrity.SignatureVerifier
import at.asitplus.signum.indispensable.integrity.SignatureVerifierProvider
import at.asitplus.signum.supreme.dsl.DSLConfigureFn

class InvalidSignature(message: String, cause: Throwable? = null): Throwable(message, cause)

interface Verifier: SignatureVerifier {

    sealed class EC
    @Throws(IllegalArgumentException::class)
    constructor (
        final override val signatureAlgorithm: SignatureAlgorithm.ECDSA,
        final override val publicKey: CryptoPublicKey.EC)
    : Verifier {
        init {
            signatureAlgorithm.requiredCurve?.let {
                require(publicKey.curve == it)
                { "Algorithm specification requires curve $it, but public key on ${publicKey.curve} was provided."}
            }
        }
        val curve inline get() = publicKey.curve
    }

    sealed class RSA
    constructor (
        final override val signatureAlgorithm: SignatureAlgorithm.RSA,
        final override val publicKey: CryptoPublicKey.RSA
    ) : Verifier
}

expect class PlatformVerifierConfiguration internal constructor(): DSL.Data
typealias ConfigurePlatformVerifier = DSLConfigureFn<PlatformVerifierConfiguration>

/** A distinguishing interface for verifiers that delegate to the underlying platform (JCA, CryptoKit, ...) */
sealed interface PlatformVerifier: Verifier
/** A distinguishing interface for verifiers that are implemented in pure Kotlin */
sealed interface KotlinVerifier: Verifier

@Throws(UnsupportedCryptoException::class)
internal expect fun checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             config: PlatformVerifierConfiguration)

internal expect fun verifyECDSAImpl
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             data: SignatureInput, signature: CryptoSignature.EC,
             config: PlatformVerifierConfiguration)

class PlatformECDSAVerifier
    internal constructor (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
                            configure: ConfigurePlatformVerifier)
    : Verifier.EC(signatureAlgorithm, publicKey), PlatformVerifier {

    private val config = DSL.resolve(::PlatformVerifierConfiguration, configure)
    init {
        checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier(signatureAlgorithm, publicKey, config)
    }
    override fun verify(data: SignatureInput, sig: CryptoSignature) = catching {
        require (sig is CryptoSignature.EC)
            { "Attempted to validate non-EC signature using EC public key" }
        return@catching verifyECDSAImpl(signatureAlgorithm, publicKey, data, sig, config).let { SignatureVerifier.Success }
    }
}

@Throws(UnsupportedCryptoException::class)
internal expect fun checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
             config: PlatformVerifierConfiguration)

/** data is guaranteed to be in RAW_BYTES format. failure should throw. */
internal expect fun verifyRSAImpl
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
             data: SignatureInput, signature: CryptoSignature.RSA,
             config: PlatformVerifierConfiguration)

class PlatformRSAVerifier
    internal constructor (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
                          configure: ConfigurePlatformVerifier)
    : Verifier.RSA(signatureAlgorithm, publicKey), PlatformVerifier {

    private val config = DSL.resolve(::PlatformVerifierConfiguration, configure)
    init {
        checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier(signatureAlgorithm, publicKey, config)
    }
    override fun verify(data: SignatureInput, sig: CryptoSignature) = catching {
        require (sig is CryptoSignature.RSA)
            { "Attempted to validate non-RSA signature using RSA public key" }
        if (data.format != null)
            throw UnsupportedOperationException("RSA with pre-hashed input is unsupported")
        return@catching verifyRSAImpl(signatureAlgorithm, publicKey, data, sig, config).let { SignatureVerifier.Success }
    }
}

class KotlinECDSAVerifier
    internal constructor (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC)
    : Verifier.EC(signatureAlgorithm, publicKey), KotlinVerifier {
    override fun verify(data: SignatureInput, sig: CryptoSignature) = catching {
        require (sig is CryptoSignature.EC)
            { "Attempted to validate non-EC signature using EC public key" }

        when (sig) {
            is CryptoSignature.EC.DefiniteLength -> require(sig.scalarByteLength == curve.scalarLength.bytes)
            is CryptoSignature.EC.IndefiniteLength -> sig.withCurve(curve)
        }
        if (!((sig.r > 0) && (sig.r < curve.order))) {
            throw InvalidSignature("r is not in [1,n-1] (r=${sig.r}, n=${curve.order})")
        }
        if (!((sig.s > 0) && (sig.s < curve.order))) {
            throw InvalidSignature("s is not in [1,n-1] (s=${sig.s}, n=${curve.order})")
        }

        val z = data.convertTo(signatureAlgorithm.digest).getOrThrow().asECDSABigInteger(curve.scalarLength)
        val sInv = sig.s.modInverse(curve.order)
        val u1 = z * sInv
        val u2 = sig.r * sInv
        val point = straussShamir(u1, curve.generator, u2, publicKey.publicPoint).run {
            tryNormalize() ?: throw InvalidSignature("(x1,y1) = additive zero") }
        if (point.x.residue.mod(curve.order) != sig.r.mod(curve.order)) {
            throw InvalidSignature("Signature is invalid: r != s")
        }
        return@catching SignatureVerifier.Success
    }
}

object SupremePlatformVerifierProvider : SignatureVerifierProvider {
    override fun verifierFor(algorithm: SignatureAlgorithm, key: CryptoPublicKey) = verifierFor(algorithm, key, null)
    fun verifierFor(algorithm: SignatureAlgorithm, key: CryptoPublicKey,
                    configure: DSLConfigureFn<PlatformVerifierConfiguration>): SignatureVerifier? =
        when (algorithm) {
            is SignatureAlgorithm.ECDSA -> {
                if (key !is CryptoPublicKey.EC)
                    throw IllegalArgumentException("Non-EC public key passed to ECDSA algorithm")
                else
                    PlatformECDSAVerifier(algorithm, key, configure)
            }
            is SignatureAlgorithm.RSA -> {
                if (key !is CryptoPublicKey.RSA)
                    throw IllegalArgumentException("Non-RSA public key passed to RSA algorithm")
                else
                    PlatformRSAVerifier(algorithm, key, configure)
            }
            else -> null
        }
}

object SupremeKotlinVerifierProvider : SignatureVerifierProvider {
    override fun verifierFor(algorithm: SignatureAlgorithm, key: CryptoPublicKey): SignatureVerifier? {
        if (algorithm !is SignatureAlgorithm.ECDSA) return null
        if (key !is CryptoPublicKey.EC)
            throw IllegalArgumentException("Non-EC public key passed to ECDSA algorithm")
        return KotlinECDSAVerifier(algorithm, key)
    }
}

/**
 * Obtains a platform verifier.
 *
 * If the specified algorithm is not natively supported by the platform, fails.
 *
 * The platform verifier can be further configured by a lambda parameter.
 *
 * @see PlatformVerifierConfiguration
 */
@Deprecated("platform distinction is unsupported in provider system; if you want a particular instantiation, ask that provider specifically")
fun SignatureAlgorithm.platformVerifierFor
            (publicKey: CryptoPublicKey, configure: ConfigurePlatformVerifier = null) =
    catching { SupremePlatformVerifierProvider.verifierFor(this, publicKey, configure) ?: throw UnsupportedCryptoException("unrecognized algorithm") }
