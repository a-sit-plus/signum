package at.asitplus.signum.supreme.sign

import at.asitplus.catchingUnwrappedAs
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.UnsupportedCryptoException
import kotlin.sequences.forEach

/**
 * Configures JVM-specific properties.
 * @see provider
 */
actual class PlatformVerifierConfiguration internal actual constructor() : DSL.Data() {
    /** The JCA provider to use, or none. */
    var provider: String? = null
}

@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             config: PlatformVerifierConfiguration)
{
    catchingUnwrappedAs(a=::UnsupportedCryptoException) {
        signatureAlgorithm.getJCASignatureInstance(config.provider)
            .initVerify(publicKey.toJcaPublicKey())
    }.getOrThrow()
}

@JvmSynthetic
internal actual suspend fun verifyECDSAImpl
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             data: SignatureInput, signature: CryptoSignature.EC,
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
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
             config: PlatformVerifierConfiguration) {
    catchingUnwrappedAs(a=::UnsupportedCryptoException) {
        signatureAlgorithm.getJCASignatureInstance(config.provider)
            .initVerify(publicKey.toJcaPublicKey())
    }.getOrThrow()
}

@JvmSynthetic
internal actual suspend fun verifyRSAImpl
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
             data: SignatureInput, signature: CryptoSignature.RSA,
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
