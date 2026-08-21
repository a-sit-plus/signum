package at.asitplus.signum.supreme.sign

import at.asitplus.catchingUnwrappedAs
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.indispensable.jcaSignatureBytes
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.JCAProviderRef
import at.asitplus.signum.indispensable.getJCASignatureInstance
import at.asitplus.signum.indispensable.getJCASignatureInstancePreHashed
import at.asitplus.signum.indispensable.integrity.SignatureInput
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.ECDSASignature
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import at.asitplus.signum.indispensable.sign.RSASignature

/**
 * Configures JVM-specific properties.
 * @see provider
 */
actual class PlatformVerifierConfiguration internal actual constructor() : DSL.Data() {
    /** The JCA provider to use, or none. */
    var provider: JCAProviderRef = JCAProviderRef.None
}

@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier
            (signatureAlgorithm: ECDSAAlgorithm, publicKey: ECDSAPublicKey,
             config: PlatformVerifierConfiguration)
{
    catchingUnwrappedAs(a=::UnsupportedCryptoException) {
        signatureAlgorithm.getJCASignatureInstance(config.provider)
            .initVerify(publicKey.toJcaPublicKey())
    }.getOrThrow()
}

@JvmSynthetic
internal actual suspend fun verifyECDSAImpl
            (signatureAlgorithm: ECDSAAlgorithm, publicKey: ECDSAPublicKey,
             data: SignatureInput, signature: ECDSASignature,
             config: PlatformVerifierConfiguration)
{
    val (input, sig) = when {
        (data.format == null) -> /* input data is not hashed, let JCA do hashing */
            Pair(data, signatureAlgorithm.getJCASignatureInstance(config.provider))
        else -> /* input data is already hashed, request raw sig from JCA */
            Pair(
                data.convertTo(signatureAlgorithm.digest).getOrThrow(),
                signatureAlgorithm.getJCASignatureInstancePreHashed(config.provider))
    }
    sig.run {
        initVerify(publicKey.toJcaPublicKey())
        input.data.forEach(this::update)
        val success = verify(signature.jcaSignatureBytes)
        if (!success)
            throw InvalidSignature("Signature is cryptographically invalid")
    }
}

@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier
            (signatureAlgorithm: RSAAlgorithm, publicKey: RSAPublicKey,
             config: PlatformVerifierConfiguration) {
    catchingUnwrappedAs(a=::UnsupportedCryptoException) {
        signatureAlgorithm.getJCASignatureInstance(config.provider)
            .initVerify(publicKey.toJcaPublicKey())
    }.getOrThrow()
}

@JvmSynthetic
internal actual suspend fun verifyRSAImpl
            (signatureAlgorithm: RSAAlgorithm, publicKey: RSAPublicKey,
             data: SignatureInput, signature: RSASignature,
             config: PlatformVerifierConfiguration)
{
    signatureAlgorithm.getJCASignatureInstance(config.provider).run {
        initVerify(publicKey.toJcaPublicKey())
        data.data.forEach(this::update)
        val success = verify(signature.jcaSignatureBytes)
        if (!success)
            throw InvalidSignature("Signature is cryptographically invalid")
    }
}
