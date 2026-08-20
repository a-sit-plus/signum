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
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.ECDSASignature
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import at.asitplus.signum.indispensable.sign.RSASignature
import at.asitplus.signum.supreme.dsl.DSLConfigureFn

class InvalidSignature(message: String, cause: Throwable? = null): Throwable(message, cause)

sealed interface SupremeVerifier: SignatureVerifier {

    sealed class EC
    @Throws(IllegalArgumentException::class)
    constructor (
        final override val signatureAlgorithm: ECDSAAlgorithm,
        final override val publicKey: ECDSAPublicKey)
    : SupremeVerifier {
        init {
            signatureAlgorithm.requiredCurve?.let {
                require(publicKey.curve == it)
                { "Algorithm specification requires curve $it, but public key on ${publicKey.curve} was provided."}
            }
        }
        val curve inline get() = publicKey.curve
    }

    /**
     * An RSA verifier.
     *
     * On iOS, platform RSA-PSS verification supports only MGF1 using the signature digest, a salt length equal to the
     * digest output length, and trailer field `1`.
     */
    sealed class RSA
    constructor (
        final override val signatureAlgorithm: RSAAlgorithm,
        final override val publicKey: RSAPublicKey
    )
    : SupremeVerifier
}

expect class PlatformVerifierConfiguration internal constructor(): DSL.Data
typealias ConfigurePlatformVerifier = DSLConfigureFn<PlatformVerifierConfiguration>

/** A distinguishing interface for verifiers that delegate to the underlying platform (JCA, CryptoKit, ...) */
sealed interface PlatformVerifier: SupremeVerifier
/** A distinguishing interface for verifiers that are implemented in pure Kotlin */
sealed interface KotlinVerifier: SupremeVerifier

@Throws(UnsupportedCryptoException::class)
internal expect fun checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier
            (signatureAlgorithm: ECDSAAlgorithm, publicKey: ECDSAPublicKey,
             config: PlatformVerifierConfiguration)

internal expect suspend fun verifyECDSAImpl
            (signatureAlgorithm: ECDSAAlgorithm, publicKey: ECDSAPublicKey,
             data: SignatureInput, signature: ECDSASignature,
             config: PlatformVerifierConfiguration)

class PlatformECDSAVerifier
    internal constructor (signatureAlgorithm: ECDSAAlgorithm, publicKey: ECDSAPublicKey,
                          configure: ConfigurePlatformVerifier)
    : SupremeVerifier.EC(signatureAlgorithm, publicKey), PlatformVerifier {

    private val config = DSL.resolve(::PlatformVerifierConfiguration, configure)
    init {
        checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier(signatureAlgorithm, publicKey, config)
    }

    override suspend fun verify(data: SignatureInput, sig: CryptoSignature) = catching {
        require(sig is ECDSASignature)
            { "Attempted to validate ${sig::class.simpleName} signature using EC public key" }
        return@catching verifyECDSAImpl(signatureAlgorithm, publicKey, data, sig, config).let { SignatureVerifier.Success }
    }
}

@Throws(UnsupportedCryptoException::class)
internal expect fun checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier
            (signatureAlgorithm: RSAAlgorithm, publicKey: RSAPublicKey,
             config: PlatformVerifierConfiguration)

/** data is guaranteed to be in RAW_BYTES format. failure should throw. */
internal expect suspend fun verifyRSAImpl
            (signatureAlgorithm: RSAAlgorithm, publicKey: RSAPublicKey,
             data: SignatureInput, signature: RSASignature,
             config: PlatformVerifierConfiguration)

class PlatformRSAVerifier
    internal constructor (signatureAlgorithm: RSAAlgorithm, publicKey: RSAPublicKey,
                          configure: ConfigurePlatformVerifier)
    : SupremeVerifier.RSA(signatureAlgorithm, publicKey), PlatformVerifier {

    private val config = DSL.resolve(::PlatformVerifierConfiguration, configure)
    init {
        checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier(signatureAlgorithm, publicKey, config)
    }
    override suspend fun verify(data: SignatureInput, sig: CryptoSignature) = catching {
        require(sig is RSASignature)
            { "Attempted to validate ${sig::class.simpleName} signature using RSA public key" }
        if (data.format != null)
            throw UnsupportedOperationException("RSA with pre-hashed input is unsupported")
        return@catching verifyRSAImpl(signatureAlgorithm, publicKey, data, sig, config).let { SignatureVerifier.Success }
    }
}

class KotlinECDSAVerifier
    internal constructor (signatureAlgorithm: ECDSAAlgorithm, publicKey: ECDSAPublicKey)
    : SupremeVerifier.EC(signatureAlgorithm, publicKey), KotlinVerifier {
    override suspend fun verify(data: SignatureInput, sig: CryptoSignature) = catching {
        require(sig is ECDSASignature)
            { "Attempted to validate ${sig::class.simpleName} signature using EC public key" }

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
    override fun verifierFor(algorithm: SignatureAlgorithm, key: CryptoPublicKey) =
        verifierFor(algorithm, key, null)
    fun verifierFor(
        algorithm: SignatureAlgorithm, key: CryptoPublicKey,
        configure: DSLConfigureFn<PlatformVerifierConfiguration>
    ): SignatureVerifier? =
        when (algorithm) {
            is ECDSAAlgorithm -> {
                if (key !is ECDSAPublicKey)
                    throw IllegalArgumentException("Non-EC public key passed to ECDSA algorithm")
                else
                    PlatformECDSAVerifier(algorithm, key, configure)
            }

            is RSAAlgorithm -> {
                if (key !is RSAPublicKey)
                    throw IllegalArgumentException("Non-RSA public key passed to RSA algorithm")
                else
                    PlatformRSAVerifier(algorithm, key, configure)
            }

            else -> null
        }
}

object SupremeKotlinVerifierProvider : SignatureVerifierProvider {
    override fun verifierFor(algorithm: SignatureAlgorithm, key: CryptoPublicKey): SignatureVerifier? {
        if (algorithm !is ECDSAAlgorithm) return null
        if (key !is ECDSAPublicKey)
            throw IllegalArgumentException("Non-EC public key passed to ECDSA algorithm")
        return KotlinECDSAVerifier(algorithm, key)
    }
}

@Deprecated("platform distinction is unsupported in provider system; if you want a particular instantiation, ask that provider specifically")
fun SignatureAlgorithm.platformVerifierFor
            (publicKey: CryptoPublicKey, configure: ConfigurePlatformVerifier = null) =
    catching { SupremePlatformVerifierProvider.verifierFor(this, publicKey, configure) ?: throw UnsupportedCryptoException("unrecognized algorithm") }
