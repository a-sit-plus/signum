package at.asitplus.crypto.provider.sign

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.datatypes.RSAPadding
import at.asitplus.crypto.datatypes.SignatureAlgorithm
import at.asitplus.crypto.datatypes.getJcaPublicKey
import at.asitplus.crypto.datatypes.jcaAlgorithmComponent
import at.asitplus.crypto.datatypes.jcaPSSParams
import at.asitplus.crypto.datatypes.jcaSignatureBytes
import at.asitplus.crypto.provider.DSL
import at.asitplus.crypto.provider.at.asitplus.crypto.provider.UnsupportedCryptoException
import java.security.Signature

actual class PlatformVerifierConfiguration internal constructor() : DSL.Data() {
    var provider: String = "BC"
}

internal actual fun checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             configure: (PlatformVerifierConfiguration.()->Unit)?)
{
}

internal actual fun checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.Rsa,
             configure: (PlatformVerifierConfiguration.()->Unit)?)
{
}

@JvmSynthetic
internal actual fun verifyECDSAImpl
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             data: SignatureInput, signature: CryptoSignature.EC,
             configure: (PlatformVerifierConfiguration.() -> Unit)?)
{
    val config = DSL.resolve(::PlatformVerifierConfiguration, configure)
    Signature.getInstance("NonewithECDSA",config.provider).run {
        initVerify(publicKey.getJcaPublicKey().getOrThrow())
        data.convertTo(signatureAlgorithm.digest).getOrThrow().data.forEach(this::update)
        val success = verify(signature.jcaSignatureBytes)
        if (!success)
            throw InvalidSignature("Signature is cryptographically invalid")
    }
}

@JvmSynthetic
internal actual fun verifyRSAImpl
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.Rsa,
             data: SignatureInput, signature: CryptoSignature.RSAorHMAC,
             configure: (PlatformVerifierConfiguration.() -> Unit)?)
{
    val config = DSL.resolve(::PlatformVerifierConfiguration, configure)
    when (signatureAlgorithm.padding) {
        RSAPadding.PKCS1 -> Signature.getInstance(
            "${signatureAlgorithm.digest.jcaAlgorithmComponent}withRSA", config.provider)
        RSAPadding.PSS -> Signature.getInstance("RSASSA-PSS", config.provider).apply {
            setParameter(signatureAlgorithm.digest.jcaPSSParams)
        }
    }.apply {
        initVerify(publicKey.getJcaPublicKey().getOrThrow())
        data.data.forEach(this::update)
        val success = verify(signature.jcaSignatureBytes)
        if (!success)
            throw InvalidSignature("Signature is cryptographically invalid")
    }
}
