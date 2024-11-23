package at.asitplus.signum.supreme.sign

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.recoverCatching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.SpecializedSignatureAlgorithm
import at.asitplus.signum.ecmath.straussShamir
import at.asitplus.signum.indispensable.KeyType
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.UnsupportedCryptoException
import at.asitplus.signum.supreme.dsl.DSLConfigureFn

class InvalidSignature(message: String, cause: Throwable? = null): Throwable(message, cause)

sealed interface Verifier<T: KeyType> {
    val signatureAlgorithm: SignatureAlgorithm<T>
    val publicKey: CryptoPublicKey<T>

    /**
     * Works around the pathological behavior of KmmResult<Unit> with .map, which would make
     * ```
     * val proxyVerify(...): KmmResult<Unit> = getVerifier().map { it.verify(...) }
     * ```
     * silently succeed (with the programmer confusing `map` and `transform`).
     */
    data object Success

    fun verify(data: SignatureInput, sig: CryptoSignature<T>): KmmResult<Success>

    sealed class EC
    @Throws(IllegalArgumentException::class)
    constructor (
        final override val signatureAlgorithm: SignatureAlgorithm.ECDSA,
        final override val publicKey: CryptoPublicKey.EC)
    : Verifier<KeyType.EC> {
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
    ): Verifier<KeyType.RSA>
}
fun <T: KeyType>Verifier<T>.verify(data: ByteArray, sig: CryptoSignature<T>) =
    verify(SignatureInput(data), sig)

expect class PlatformVerifierConfiguration internal constructor(): DSL.Data
typealias ConfigurePlatformVerifier = DSLConfigureFn<PlatformVerifierConfiguration>

/** A distinguishing interface for verifiers that delegate to the underlying platform (JCA, CryptoKit, ...) */
sealed interface PlatformVerifier<T: KeyType>: Verifier<T>
/** A distinguishing interface for verifiers that are implemented in pure Kotlin */
sealed interface KotlinVerifier<T: KeyType>: Verifier<T>

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
    : Verifier.EC(signatureAlgorithm, publicKey), PlatformVerifier<KeyType.EC> {

    private val config = DSL.resolve(::PlatformVerifierConfiguration, configure)
    init {
        checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier(signatureAlgorithm, publicKey, config)
    }
    override fun verify(data: SignatureInput, sig: CryptoSignature<KeyType.EC>) = catching {
        require (sig is CryptoSignature.EC)
            { "Attempted to validate non-EC signature using EC public key" }
        return@catching verifyECDSAImpl(signatureAlgorithm, publicKey, data, sig, config).let { Verifier.Success }
    }
}

@Throws(UnsupportedCryptoException::class)
internal expect fun checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
             config: PlatformVerifierConfiguration)

/** data is guaranteed to be in RAW_BYTES format. failure should throw. */
internal expect fun verifyRSAImpl
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
             data: SignatureInput, signature: CryptoSignature.RSAorHMAC,
             config: PlatformVerifierConfiguration)

class PlatformRSAVerifier
    internal constructor (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
                          configure: ConfigurePlatformVerifier)
    : Verifier.RSA(signatureAlgorithm, publicKey), PlatformVerifier<KeyType.RSA> {

    private val config = DSL.resolve(::PlatformVerifierConfiguration, configure)
    init {
        checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier(signatureAlgorithm, publicKey, config)
    }
    override fun verify(data: SignatureInput, sig: CryptoSignature<KeyType.RSA>) = catching {
        require (sig is CryptoSignature.RSAorHMAC)
            { "Attempted to validate non-RSA signature using RSA public key" }
        if (data.format != null)
            throw UnsupportedOperationException("RSA with pre-hashed input is unsupported")
        return@catching verifyRSAImpl(signatureAlgorithm, publicKey, data, sig, config).let { Verifier.Success }
    }
}

class KotlinECDSAVerifier
    internal constructor (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC)
    : Verifier.EC(signatureAlgorithm, publicKey), KotlinVerifier<KeyType.EC> {
    override fun verify(data: SignatureInput, sig: CryptoSignature<KeyType.EC>) = catching {
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
fun <K: KeyType>SignatureAlgorithm<out K>.verifierFor
            (publicKey: CryptoPublicKey<K>, configure: ConfigurePlatformVerifier = null) =
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
fun <K: KeyType>SignatureAlgorithm<out K>.platformVerifierFor
            (publicKey: CryptoPublicKey<K>, configure: ConfigurePlatformVerifier = null) =
    verifierForImpl(publicKey, configure, allowKotlin = false)

private fun <K: KeyType>SignatureAlgorithm<out K>.verifierForImpl
            (publicKey: CryptoPublicKey<K>, configure: ConfigurePlatformVerifier,
             allowKotlin: Boolean): KmmResult<Verifier<K>> =
    when (this) {
        is SignatureAlgorithm.ECDSA -> verifierForImpl(publicKey, configure, allowKotlin)
        is SignatureAlgorithm.RSA -> verifierForImpl(publicKey, configure, allowKotlin)
        is SignatureAlgorithm.HMAC ->
            KmmResult.failure(IllegalArgumentException("HMAC is unsupported"))
    } as KmmResult<Verifier<K>>

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
            (publicKey: CryptoPublicKey.EC, configure: ConfigurePlatformVerifier = null) =
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
            (publicKey: CryptoPublicKey.EC, configure: ConfigurePlatformVerifier = null) =
    verifierForImpl(publicKey, configure, allowKotlin = false)

private fun SignatureAlgorithm.ECDSA.verifierForImpl
            (publicKey: CryptoPublicKey.EC, configure: ConfigurePlatformVerifier,
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
            (publicKey: CryptoPublicKey.RSA, configure: ConfigurePlatformVerifier = null) =
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
            (publicKey: CryptoPublicKey.RSA, configure: ConfigurePlatformVerifier = null) =
    verifierForImpl(publicKey, configure, allowKotlin = false)

private fun SignatureAlgorithm.RSA.verifierForImpl
            (publicKey: CryptoPublicKey.RSA, configure: ConfigurePlatformVerifier,
            /*TODO unused param???*/ allowKotlin: Boolean): KmmResult<Verifier.RSA> =
    catching { PlatformRSAVerifier(this, publicKey, configure) }

/** @see [SignatureAlgorithm.verifierFor] */
fun <K: KeyType>SpecializedSignatureAlgorithm<K>.verifierFor
            (publicKey: CryptoPublicKey<K>, configure: ConfigurePlatformVerifier = null) =
    this.algorithm.verifierFor(publicKey, configure)

/** @see [SignatureAlgorithm.platformVerifierFor] */
fun <K: KeyType>SpecializedSignatureAlgorithm<K>.platformVerifierFor
            (publicKey: CryptoPublicKey<K>, configure: ConfigurePlatformVerifier = null) =
    this.algorithm.platformVerifierFor(publicKey, configure)
