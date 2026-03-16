package at.asitplus.signum.supreme.sign

import at.asitplus.catchingUnwrappedAs
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.getJCASignatureInstance
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.indispensable.jcaAlgorithmComponent
import at.asitplus.signum.indispensable.jcaSignatureBytes
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.EcdsaSignatureAlgorithm
import at.asitplus.signum.indispensable.RsaSignatureAlgorithm
import at.asitplus.signum.indispensable.key.EcPublicKey
import at.asitplus.signum.indispensable.key.RsaPublicKey
import at.asitplus.signum.indispensable.signature.EcSignature
import at.asitplus.signum.indispensable.signature.RsaSignature

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
        null -> java.security.Signature.getInstance(alg)
        else -> java.security.Signature.getInstance(alg, p)
    }

@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier
            (signatureAlgorithm: EcdsaSignatureAlgorithm, publicKey: EcPublicKey,
             config: PlatformVerifierConfiguration)
{
    catchingUnwrappedAs(a=::UnsupportedCryptoException) {
        getSigInstance("${signatureAlgorithm.digest.jcaAlgorithmComponent}withECDSA", config.provider)
            .initVerify(publicKey.toJcaPublicKey().getOrThrow())
    }.getOrThrow()
}

@JvmSynthetic
internal actual fun verifyECDSAImpl
    (signatureAlgorithm: EcdsaSignatureAlgorithm, publicKey: EcPublicKey,
     data: SignatureInput, signature: EcSignature,
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

private fun getRSAInstance(alg: RsaSignatureAlgorithm, config: PlatformVerifierConfiguration) =
    alg.getJCASignatureInstance(config.provider).getOrThrow()

@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier
            (signatureAlgorithm: RsaSignatureAlgorithm, publicKey: RsaPublicKey,
             config: PlatformVerifierConfiguration)
{
    catchingUnwrappedAs(a=::UnsupportedCryptoException) {
        getRSAInstance(signatureAlgorithm, config)
            .initVerify(publicKey.toJcaPublicKey().getOrThrow())
    }.getOrThrow()
}

@JvmSynthetic
internal actual fun verifyRSAImpl
    (signatureAlgorithm: RsaSignatureAlgorithm, publicKey: RsaPublicKey,
     data: SignatureInput, signature: RsaSignature,
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
