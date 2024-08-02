package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.getJcaPublicKey
import at.asitplus.signum.indispensable.jcaAlgorithmComponent
import at.asitplus.signum.indispensable.jcaPSSParams
import at.asitplus.signum.indispensable.jcaSignatureBytes
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.UnsupportedCryptoException
import at.asitplus.signum.supreme.sign.InvalidSignature
import at.asitplus.signum.supreme.sign.PlatformVerifierConfiguration
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.wrapping
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
             config: PlatformVerifierConfiguration
)
{
    wrapping(asA=::UnsupportedCryptoException) {
        getSigInstance("${signatureAlgorithm.digest.jcaAlgorithmComponent}withECDSA", config.provider)
            .initVerify(publicKey.getJcaPublicKey().getOrThrow())
    }.getOrThrow()
}

@JvmSynthetic
internal actual fun verifyECDSAImpl
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             data: SignatureInput, signature: CryptoSignature.EC,
             config: PlatformVerifierConfiguration
)
{
    val (input, alg) = when {
        (data.format == null) -> /* input data is not hashed, let JCA do hashing */
            Pair(data, "${signatureAlgorithm.digest.jcaAlgorithmComponent}withECDSA")
        else -> /* input data is already hashed, request raw sig from JCA */
            Pair(data.convertTo(signatureAlgorithm.digest).getOrThrow(), "NONEwithECDSA")
    }
    getSigInstance(alg, config.provider).run {
        initVerify(publicKey.getJcaPublicKey().getOrThrow())
        input.data.forEach(this::update)
        val success = verify(signature.jcaSignatureBytes)
        if (!success)
            throw InvalidSignature("Signature is cryptographically invalid")
    }
}

private fun getRSAInstance(alg: SignatureAlgorithm.RSA, config: PlatformVerifierConfiguration) =
    when (alg.padding) {
        RSAPadding.PKCS1 -> getSigInstance(
            "${alg.digest.jcaAlgorithmComponent}withRSA", config.provider)
        RSAPadding.PSS -> getSigInstance("RSASSA-PSS", config.provider).apply {
            setParameter(alg.digest.jcaPSSParams)
        }
    }

@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.Rsa,
             config: PlatformVerifierConfiguration
) {
    wrapping(asA=::UnsupportedCryptoException) {
        getRSAInstance(signatureAlgorithm, config)
            .initVerify(publicKey.getJcaPublicKey().getOrThrow())
    }.getOrThrow()
}

@JvmSynthetic
internal actual fun verifyRSAImpl
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.Rsa,
             data: SignatureInput, signature: CryptoSignature.RSAorHMAC,
             config: PlatformVerifierConfiguration
)
{
    getRSAInstance(signatureAlgorithm, config).run {
        initVerify(publicKey.getJcaPublicKey().getOrThrow())
        data.data.forEach(this::update)
        val success = verify(signature.jcaSignatureBytes)
        if (!success)
            throw InvalidSignature("Signature is cryptographically invalid")
    }
}
