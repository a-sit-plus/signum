package at.asitplus.crypto.provider.sign

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.SignatureAlgorithm
import at.asitplus.crypto.ecmath.straussShamir
import at.asitplus.crypto.provider.DSL
import at.asitplus.crypto.provider.at.asitplus.crypto.provider.UnsupportedCryptoException

class InvalidSignature(message: String): Throwable(message)

sealed interface Verifier {
    val signatureAlgorithm: SignatureAlgorithm
    val publicKey: CryptoPublicKey

    fun verify(data: SignatureInput, sig: CryptoSignature): KmmResult<Unit>

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
        final override val publicKey: CryptoPublicKey.Rsa)
    : Verifier
}
fun Verifier.verify(data: ByteArray, sig: CryptoSignature) =
    verify(SignatureInput(data), sig)

expect class PlatformVerifierConfiguration: DSL.Data

/** A distinguishing interface for verifiers that delegate to the underlying platform (JCA, CryptoKit, ...) */
sealed interface PlatformVerifier: Verifier
/** A distinguishing interface for verifiers that are implemented in pure Kotlin */
sealed interface KotlinVerifier: Verifier

@Throws(UnsupportedCryptoException::class)
internal expect fun checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             configure: (PlatformVerifierConfiguration.()->Unit)?)

internal expect fun verifyECDSAImpl
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             data: SignatureInput, signature: CryptoSignature.EC,
             configure: (PlatformVerifierConfiguration.() -> Unit)?)
class PlatformECDSAVerifier
    internal constructor (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
                            private val configure: (PlatformVerifierConfiguration.()->Unit)? = null)
    : Verifier.EC(signatureAlgorithm, publicKey), PlatformVerifier {
    init {
        checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier(signatureAlgorithm, publicKey, configure)
    }
    override fun verify(data: SignatureInput, sig: CryptoSignature) = catching {
        require (sig is CryptoSignature.EC)
            { "Attempted to validate non-EC signature using EC public key" }
        return@catching verifyECDSAImpl(signatureAlgorithm, publicKey, data, sig, configure)
    }
}

@Throws(UnsupportedCryptoException::class)
internal expect fun checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.Rsa,
             configure: (PlatformVerifierConfiguration.()->Unit)?)

/** data is guaranteed to be in RAW_BYTES format. failure should throw. */
internal expect fun verifyRSAImpl
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.Rsa,
             data: SignatureInput, signature: CryptoSignature.RSAorHMAC,
             configure: (PlatformVerifierConfiguration.() -> Unit)?)
class PlatformRSAVerifier
    internal constructor (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.Rsa,
                          private val configure: (PlatformVerifierConfiguration.()->Unit)? = null)
    : Verifier.RSA(signatureAlgorithm, publicKey), PlatformVerifier {
    init {
        checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier(signatureAlgorithm, publicKey, configure)
    }
    override fun verify(data: SignatureInput, sig: CryptoSignature) = catching {
        require (sig is CryptoSignature.RSAorHMAC)
            { "Attempted to validate non-RSA signature using RSA public key" }
        if (data.format != null)
            throw UnsupportedOperationException("RSA with pre-hashed input is unsupported")
        return@catching verifyRSAImpl(signatureAlgorithm, publicKey, data, sig, configure)
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

        val z = data.convertTo(signatureAlgorithm.digest).getOrThrow().asBigInteger(curve.scalarLength)
        val sInv = sig.s.modInverse(curve.order)
        val u1 = z * sInv
        val u2 = sig.r * sInv
        val point = straussShamir(u1, curve.generator, u2, publicKey.publicPoint).run {
            tryNormalize() ?: throw InvalidSignature("(x1,y1) = additive zero") }
        if (point.x.residue.mod(curve.order) != sig.r.mod(curve.order)) {
            throw InvalidSignature("Signature is invalid: r != s")
        }
    }
}

/** Obtains a verifier. If the specified algorithm is not natively supported by the platform, attempts to fall back to a pure-Kotlin implementation. */
fun SignatureAlgorithm.verifierFor(publicKey: CryptoPublicKey) =
    verifierForImpl(publicKey, allowKotlin = true)

/** Obtains a platform verifier. If the specified algorithm is unsupported by the platform, fails. */
fun SignatureAlgorithm.platformVerifierFor(publicKey: CryptoPublicKey) =
    verifierForImpl(publicKey, allowKotlin = false)

private fun SignatureAlgorithm.verifierForImpl(publicKey: CryptoPublicKey, allowKotlin: Boolean): KmmResult<out Verifier> =
    when (this) {
        is SignatureAlgorithm.ECDSA -> {
            require(publicKey is CryptoPublicKey.EC)
                { "Non-EC public key passed to ECDSA algorithm"}
            verifierForImpl(publicKey, allowKotlin)
        }
        is SignatureAlgorithm.RSA -> {
            require(publicKey is CryptoPublicKey.Rsa)
                { "Non-RSA public key passed to RSA algorithm"}
            verifierForImpl(publicKey, allowKotlin)
        }
        is SignatureAlgorithm.HMAC -> throw UnsupportedCryptoException("HMAC is unsupported")
    }

private fun <R, T:R> KmmResult<T>.recoverCatching(fn: (Throwable)->R): KmmResult<out R> =
    when (val x = exceptionOrNull()) {
        null -> this
        else -> catching { fn(x) }
    }

fun SignatureAlgorithm.ECDSA.verifierFor(publicKey: CryptoPublicKey.EC) =
    verifierForImpl(publicKey, allowKotlin = true)

fun SignatureAlgorithm.ECDSA.platformVerifierFor(publicKey: CryptoPublicKey.EC) =
    verifierForImpl(publicKey, allowKotlin = false)

private fun SignatureAlgorithm.ECDSA.verifierForImpl(publicKey: CryptoPublicKey.EC, allowKotlin: Boolean): KmmResult<out Verifier.EC> =
    catching { PlatformECDSAVerifier(this, publicKey) }
    .recoverCatching {
        if (allowKotlin && (it is UnsupportedCryptoException)) KotlinECDSAVerifier(this, publicKey)
        else throw it
    }

fun SignatureAlgorithm.RSA.verifierFor(publicKey: CryptoPublicKey.Rsa) =
    verifierForImpl(publicKey, allowKotlin = true)

fun SignatureAlgorithm.RSA.platformVerifierFor(publicKey: CryptoPublicKey.Rsa) =
    verifierForImpl(publicKey, allowKotlin = false)

private fun SignatureAlgorithm.RSA.verifierForImpl(publicKey: CryptoPublicKey.Rsa, allowKotlin: Boolean): KmmResult<out Verifier.RSA> =
    catching { PlatformRSAVerifier(this, publicKey) }
