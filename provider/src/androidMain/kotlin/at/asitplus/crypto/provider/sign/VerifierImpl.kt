package at.asitplus.crypto.provider.sign

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.RSAPadding
import at.asitplus.crypto.datatypes.SignatureAlgorithm
import at.asitplus.crypto.datatypes.getJcaPublicKey
import at.asitplus.crypto.datatypes.jcaAlgorithmComponent
import at.asitplus.crypto.datatypes.jcaPSSParams
import at.asitplus.crypto.datatypes.jcaSignatureBytes
import java.security.Signature
import java.security.SignatureException

@JvmSynthetic
internal actual fun verifyECDSAImpl
    (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
     data: SignatureInput, signature: CryptoSignature.EC)
{
    Signature.getInstance("NonewithECDSA","AndroidKeyStore").run {
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
     data: SignatureInput, signature: CryptoSignature.RSAorHMAC)
{
    when (signatureAlgorithm.padding) {
        RSAPadding.PKCS1 -> Signature.getInstance(
            "${signatureAlgorithm.digest.jcaAlgorithmComponent}withRSA", "AndroidKeyStore")
        RSAPadding.PSS -> Signature.getInstance("RSASSA-PSS").apply {
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
