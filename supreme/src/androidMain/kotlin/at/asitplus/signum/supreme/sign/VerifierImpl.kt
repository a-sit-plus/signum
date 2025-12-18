package at.asitplus.signum.supreme.sign

import at.asitplus.catchingUnwrappedAs
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.indispensable.jcaAlgorithmComponent
import at.asitplus.signum.indispensable.jcaSignatureBytes
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.UnsupportedCryptoException
import java.security.Signature

/**
 * Configures JVM-specific properties.
 * @see provider
 */
actual class PlatformVerifierConfiguration internal actual constructor() : DSL.Data() {
    /** The JCA provider to use, or none. */
    var provider: String? = null
}

private fun getSigInstance(alg: String, p: String?) =
    when (p) {
        null -> Signature.getInstance(alg)
        else -> Signature.getInstance(alg, p)
    }

@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             config: PlatformVerifierConfiguration)
{
    catchingUnwrappedAs(a=::UnsupportedCryptoException) {
        getSigInstance("${signatureAlgorithm.digest.jcaAlgorithmComponent}withECDSA", config.provider)
            .initVerify(publicKey.toJcaPublicKey().getOrThrow())
    }.getOrThrow()
}

@JvmSynthetic
internal actual suspend fun verifyECDSAImpl
    (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
     data: SignatureInput, signature: CryptoSignature.EC,
     config: PlatformVerifierConfiguration)
{
    val (input, alg) = when {
        (data.format == null) -> /* input data is not hashed, let JCA do hashing */
            Pair(data, "${signatureAlgorithm.digest.jcaAlgorithmComponent}withECDSA")
        else -> /* input data is already hashed, request raw sig from JCA */
            Pair(data.convertTo(signatureAlgorithm.digest).getOrThrow(), "NONEwithECDSA")
    }
    getSigInstance(alg, config.provider).run {
        initVerify(publicKey.toJcaPublicKey().getOrThrow())
        input.data.forEach(this::update)
        val success = verify(signature.jcaSignatureBytes)
        if (!success)
            throw InvalidSignature("Signature is cryptographically invalid")
    }
}

private fun getRSAInstance(alg: SignatureAlgorithm.RSA, config: PlatformVerifierConfiguration) =
    getSigInstance(when (alg.padding) {
        RSAPadding.PKCS1 -> "${alg.digest.jcaAlgorithmComponent}withRSA"
        RSAPadding.PSS -> "${alg.digest.jcaAlgorithmComponent}withRSA/PSS"
    }, config.provider)

@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
             config: PlatformVerifierConfiguration)
{
    catchingUnwrappedAs(a=::UnsupportedCryptoException) {
        getRSAInstance(signatureAlgorithm, config)
            .initVerify(publicKey.toJcaPublicKey().getOrThrow())
    }.getOrThrow()
}

@JvmSynthetic
internal actual suspend fun verifyRSAImpl
    (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
     data: SignatureInput, signature: CryptoSignature.RSA,
     config: PlatformVerifierConfiguration)
{
    getRSAInstance(signatureAlgorithm, config).run {
        initVerify(publicKey.toJcaPublicKey().getOrThrow())
        data.data.forEach(this::update)
        val success = verify(signature.jcaSignatureBytes)
        if (!success)
            throw InvalidSignature("Signature is cryptographically invalid")
    }
}
