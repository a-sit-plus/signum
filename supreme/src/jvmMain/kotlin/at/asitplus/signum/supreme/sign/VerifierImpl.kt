package at.asitplus.signum.supreme.sign

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.getJCASignatureInstance
import at.asitplus.signum.indispensable.getJcaPublicKey
import at.asitplus.signum.indispensable.verifyWithJCA
import at.asitplus.signum.indispensable.verifyWithJCAPreHashed
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.UnsupportedCryptoException
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

@OptIn(HazardousMaterials::class)
@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             config: PlatformVerifierConfiguration)
{
    wrapping(asA=::UnsupportedCryptoException) {
        signatureAlgorithm.getJCASignatureInstance(config.provider, forSigning = false)
            .getOrThrow().initVerify(publicKey.getJcaPublicKey().getOrThrow())
    }.getOrThrow()
}

@JvmSynthetic
internal actual fun verifyECDSAImpl
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             data: SignatureInput, signature: CryptoSignature.EC,
             config: PlatformVerifierConfiguration)
{
    val preHashed = (data.format != null)
    if (preHashed) {
        require(data.format == signatureAlgorithm.preHashedSignatureFormat)
        { "Pre-hashed data (format ${data.format}) unsupported for algorithm $signatureAlgorithm" }
    }
    val block: Signature.(ByteArray) -> Boolean = { sig ->
        initVerify(publicKey.getJcaPublicKey().getOrThrow())
        data.data.forEach { update(it) }
        verify(sig)
    }
    if (preHashed)
        signatureAlgorithm.verifyWithJCAPreHashed(provider = config.provider, signature, block).getOrThrow()
    else
        signatureAlgorithm.verifyWithJCA(provider = config.provider, signature, block).getOrThrow()
}

@OptIn(HazardousMaterials::class)
@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
             config: PlatformVerifierConfiguration) {
    wrapping(asA=::UnsupportedCryptoException) {
        signatureAlgorithm.getJCASignatureInstance(config.provider, forSigning = false)
            .getOrThrow().initVerify(publicKey.getJcaPublicKey().getOrThrow())
    }.getOrThrow()
}

@JvmSynthetic
internal actual fun verifyRSAImpl
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
             data: SignatureInput, signature: CryptoSignature.RSAorHMAC,
             config: PlatformVerifierConfiguration)
{
    signatureAlgorithm.verifyWithJCA(provider = config.provider, signature) { sig ->
        initVerify(publicKey.getJcaPublicKey().getOrThrow())
        data.data.forEach(this::update)
        verify(sig)
    }.getOrThrow()
}
