package at.asitplus.crypto.provider.sign

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.RSAPadding
import at.asitplus.crypto.datatypes.SignatureAlgorithm
import at.asitplus.crypto.datatypes.getJcaPublicKey
import at.asitplus.crypto.datatypes.jcaAlgorithmComponent
import at.asitplus.crypto.datatypes.jcaPSSParams
import at.asitplus.crypto.datatypes.jcaSignatureBytes
import at.asitplus.crypto.provider.dsl.DSL
import at.asitplus.crypto.provider.UnsupportedCryptoException
import java.security.Signature

actual class PlatformVerifierConfiguration internal constructor() : DSL.Data() {
    var provider: String? = null
}

@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             configure: (PlatformVerifierConfiguration.()->Unit)?)
{
}

@Throws(UnsupportedCryptoException::class)
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

    val (input, alg) = when {
        (data.format == null) -> /* input data is not hashed, let JCA do hashing */
            Pair(data, "${signatureAlgorithm.digest.jcaAlgorithmComponent}withECDSA")
        else -> /* input data is already hashed, request raw sig from JCA */
            Pair(data.convertTo(signatureAlgorithm.digest).getOrThrow(), "NONEwithECDSA")
    }
    when (val p = config.provider) {
        null -> Signature.getInstance(alg)
        else -> Signature.getInstance(alg, p)
    }.run {
        initVerify(publicKey.getJcaPublicKey().getOrThrow())
        input.data.forEach(this::update)
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

    val alg = when (signatureAlgorithm.padding) {
        RSAPadding.PKCS1 -> "${signatureAlgorithm.digest.jcaAlgorithmComponent}withRSA"
        RSAPadding.PSS -> "${signatureAlgorithm.digest.jcaAlgorithmComponent}withRSA/PSS"
    }
    when (val p = config.provider) {
        null -> Signature.getInstance(alg)
        else-> Signature.getInstance(alg, p)
    }.run {
        initVerify(publicKey.getJcaPublicKey().getOrThrow())
        data.data.forEach(this::update)
        val success = verify(signature.jcaSignatureBytes)
        if (!success)
            throw InvalidSignature("Signature is cryptographically invalid")
    }
}
