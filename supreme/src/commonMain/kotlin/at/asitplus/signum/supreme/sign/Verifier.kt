package at.asitplus.signum.supreme.sign

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.recoverCatching
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.PrivateKey
import at.asitplus.signum.indispensable.Signature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.SpecializedSignatureAlgorithm
import at.asitplus.signum.ecmath.straussShamir
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
class InvalidSignature(message: String, cause: Throwable? = null): Throwable(message, cause)

sealed interface Verifier {
    val signatureAlgorithm: SignatureAlgorithm
    val publicKey: PublicKey

    /**
     * Works around the pathological behavior of KmmResult<Unit> with .map, which would make
     * ```
     * val proxyVerify(...): KmmResult<Unit> = getVerifier().map { it.verify(...) }
     * ```
     * silently succeed (with the programmer confusing `map` and `transform`).
     */
    data object Success

    fun verify(data: SignatureInput, sig: Signature): KmmResult<Success>

    sealed class EC
    @Throws(IllegalArgumentException::class)
    constructor (
        final override val signatureAlgorithm: SignatureAlgorithm.ECDSA,
        final override val publicKey: PublicKey.EC)
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
        final override val publicKey: PublicKey.RSA
    )
    : Verifier
}
fun Verifier.verify(data: ByteArray, sig: Signature) =
    verify(SignatureInput(data), sig)

expect class PlatformVerifierConfiguration internal constructor(): DSL.Data
typealias ConfigurePlatformVerifier = DSLConfigureFn<PlatformVerifierConfiguration>

/** A distinguishing interface for verifiers that delegate to the underlying platform (JCA, CryptoKit, ...) */
sealed interface PlatformVerifier: Verifier
/** A distinguishing interface for verifiers that are implemented in pure Kotlin */
sealed interface KotlinVerifier: Verifier

@Throws(UnsupportedCryptoException::class)
internal expect fun checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: PublicKey.EC,
             config: PlatformVerifierConfiguration)

internal expect fun verifyECDSAImpl
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: PublicKey.EC,
             data: SignatureInput, signature: Signature.EC,
             config: PlatformVerifierConfiguration)

class PlatformECDSAVerifier
    internal constructor (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: PublicKey.EC,
                            configure: ConfigurePlatformVerifier)
    : Verifier.EC(signatureAlgorithm, publicKey), PlatformVerifier {

    private val config = DSL.resolve(::PlatformVerifierConfiguration, configure)
    init {
        checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier(signatureAlgorithm, publicKey, config)
    }
    override fun verify(data: SignatureInput, sig: Signature) = catching {
        require (sig is Signature.EC)
            { "Attempted to validate non-EC signature using EC public key" }
        return@catching verifyECDSAImpl(signatureAlgorithm, publicKey, data, sig, config).let { Verifier.Success }
    }
}

@Throws(UnsupportedCryptoException::class)
internal expect fun checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: PublicKey.RSA,
             config: PlatformVerifierConfiguration)

/** data is guaranteed to be in RAW_BYTES format. failure should throw. */
internal expect fun verifyRSAImpl
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: PublicKey.RSA,
             data: SignatureInput, signature: Signature.RSA,
             config: PlatformVerifierConfiguration)

class PlatformRSAVerifier
    internal constructor (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: PublicKey.RSA,
                          configure: ConfigurePlatformVerifier)
    : Verifier.RSA(signatureAlgorithm, publicKey), PlatformVerifier {

    private val config = DSL.resolve(::PlatformVerifierConfiguration, configure)
    init {
        checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier(signatureAlgorithm, publicKey, config)
    }
    override fun verify(data: SignatureInput, sig: Signature) = catching {
        require (sig is Signature.RSA)
            { "Attempted to validate non-RSA signature using RSA public key" }
        if (data.format != null)
            throw UnsupportedOperationException("RSA with pre-hashed input is unsupported")
        return@catching verifyRSAImpl(signatureAlgorithm, publicKey, data, sig, config).let { Verifier.Success }
    }
}

class KotlinECDSAVerifier
    internal constructor (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: PublicKey.EC)
    : Verifier.EC(signatureAlgorithm, publicKey), KotlinVerifier {
    override fun verify(data: SignatureInput, sig: Signature) = catching {
        require (sig is Signature.EC)
            { "Attempted to validate non-EC signature using EC public key" }

        when (sig) {
            is Signature.EC.DefiniteLength -> require(sig.scalarByteLength == curve.scalarLength.bytes)
            is Signature.EC.IndefiniteLength -> sig.withCurve(curve)
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
        return@catching Verifier.Success
    }
}

/**
 * Obtains a verifier.
 *
 * If the specified algorithm is not natively supported by the platform,
 * attempts to fall back to a pure-Kotlin implementation.
 *
 * The platform verifier can be further configured by a lambda parameter.
 *
 * @see PlatformVerifierConfiguration
 */
fun SignatureAlgorithm.verifierFor
            (publicKey: PublicKey, configure: ConfigurePlatformVerifier = null) =
    verifierForImpl(publicKey, configure, allowKotlin = true)

/**
 * Obtains a platform verifier.
 *
 * If the specified algorithm is not natively supported by the platform, fails.
 *
 * The platform verifier can be further configured by a lambda parameter.
 *
 * @see PlatformVerifierConfiguration
 */
fun SignatureAlgorithm.platformVerifierFor
            (publicKey: PublicKey, configure: ConfigurePlatformVerifier = null) =
    verifierForImpl(publicKey, configure, allowKotlin = false)

private fun SignatureAlgorithm.verifierForImpl
            (publicKey: PublicKey, configure: ConfigurePlatformVerifier,
             allowKotlin: Boolean): KmmResult<Verifier> =
    when (this) {
        is SignatureAlgorithm.ECDSA -> {
            if(publicKey !is PublicKey.EC)
                KmmResult.failure(IllegalArgumentException("Non-EC public key passed to ECDSA algorithm"))
            else
                verifierForImpl(publicKey, configure, allowKotlin)
        }
        is SignatureAlgorithm.RSA -> {
            if (publicKey !is PublicKey.RSA)
                KmmResult.failure(IllegalArgumentException("Non-RSA public key passed to RSA algorithm"))
            else
                verifierForImpl(publicKey, configure, allowKotlin)
        }
    }

/**
 * Obtains a verifier.
 *
 * If the specified algorithm is not natively supported by the platform,
 * attempts to fall back to a pure-Kotlin implementation.
 *
 * The platform verifier can be further configured by a lambda parameter.
 *
 * @see PlatformVerifierConfiguration
 */
fun SignatureAlgorithm.ECDSA.verifierFor
            (publicKey: PublicKey.EC, configure: ConfigurePlatformVerifier = null) =
    verifierForImpl(publicKey, configure, allowKotlin = true)

/**
 * Obtains a platform verifier.
 *
 * If the specified algorithm is not natively supported by the platform, fails.
 *
 * The platform verifier can be further configured by a lambda parameter.
 *
 * @see PlatformVerifierConfiguration
 */
fun SignatureAlgorithm.ECDSA.platformVerifierFor
            (publicKey: PublicKey.EC, configure: ConfigurePlatformVerifier = null) =
    verifierForImpl(publicKey, configure, allowKotlin = false)

private fun SignatureAlgorithm.ECDSA.verifierForImpl
            (publicKey: PublicKey.EC, configure: ConfigurePlatformVerifier,
             allowKotlin: Boolean): KmmResult<Verifier.EC> =
    catching { PlatformECDSAVerifier(this, publicKey, configure) }
    .recoverCatching {
        if (allowKotlin && (it is UnsupportedCryptoException))
            KotlinECDSAVerifier(this, publicKey)
        else throw it
    }

/**
 * Obtains a verifier.
 *
 * If the specified algorithm is not natively supported by the platform,
 * attempts to fall back to a pure-Kotlin implementation.
 *
 * The platform verifier can be further configured by a lambda parameter.
 *
 * @see PlatformVerifierConfiguration
 */
fun SignatureAlgorithm.RSA.verifierFor
            (publicKey: PublicKey.RSA, configure: ConfigurePlatformVerifier = null) =
    verifierForImpl(publicKey, configure, allowKotlin = true)

/**
 * Obtains a platform verifier.
 *
 * If the specified algorithm is not natively supported by the platform, fails.
 *
 * The platform verifier can be further configured by a lambda parameter.
 *
 * @see PlatformVerifierConfiguration
 */
fun SignatureAlgorithm.RSA.platformVerifierFor
            (publicKey: PublicKey.RSA, configure: ConfigurePlatformVerifier = null) =
    verifierForImpl(publicKey, configure, allowKotlin = false)

private fun SignatureAlgorithm.RSA.verifierForImpl
            (publicKey: PublicKey.RSA, configure: ConfigurePlatformVerifier,
             allowKotlin: Boolean): KmmResult<Verifier.RSA> =
    catching { PlatformRSAVerifier(this, publicKey, configure) }

/** @see [SignatureAlgorithm.verifierFor] */
fun SpecializedSignatureAlgorithm.verifierFor
            (publicKey: PublicKey, configure: ConfigurePlatformVerifier = null) =
    this.algorithm.verifierFor(publicKey, configure)

/** @see [SignatureAlgorithm.platformVerifierFor] */
fun SpecializedSignatureAlgorithm.platformVerifierFor
            (publicKey: PublicKey, configure: ConfigurePlatformVerifier = null) =
    this.algorithm.platformVerifierFor(publicKey, configure)
