package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPrivateKey
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSAPrivateKey
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

object IndispensableJcaExtensionProvider : JcaMappingProvider {
    override fun getJCASignatureInstance(algorithm: SignatureAlgorithm, jcaProvider: String?) = when (algorithm) {
        is ECDSAAlgorithm -> when (val digest = algorithm.digest) {
            is WellKnownDigest? -> sigGetInstance("${digest.jcaAlgorithmComponent}withECDSA", jcaProvider)
            else -> null
        }
        is RSAAlgorithm -> getRSAPlatformSignatureInstance(algorithm, jcaProvider)
        else -> null
    }

    override fun getJCASignatureInstancePreHashed(algorithm: SignatureAlgorithm, jcaProvider: String?) = when (algorithm) {
        is ECDSAAlgorithm ->
            sigGetInstance("NONEwithECDSA", jcaProvider)
        else -> null
    }

    override fun cryptoPublicKeyToJcaPublicKey(publicKey: CryptoPublicKey) = when(publicKey) {
        is ECDSAPublicKey -> publicKey.toJcaPublicKey()
        is RSAPublicKey -> publicKey.toJcaPublicKey()
        else -> null
    }

    override fun jcaPublicKeyToCryptoPublicKey(publicKey: PublicKey) = when(publicKey) {
        is java.security.interfaces.RSAPublicKey -> publicKey.toCryptoPublicKey()
        is java.security.interfaces.ECPublicKey -> publicKey.toCryptoPublicKey()
        else -> null
    }

    override fun cryptoPrivateKeyToJcaPrivateKey(privateKey: CryptoPrivateKey) =
        when (privateKey) {
            is RSAPrivateKey -> privateKey.toJcaPrivateKey()
            is ECDSAPrivateKey -> privateKey.toJcaPrivateKey()
            else -> null
        }

    override fun jcaPrivateKeyToCryptoPrivateKey(privateKey: PrivateKey) =
        when (privateKey) {
            is java.security.interfaces.RSAPrivateKey -> privateKey.toCryptoPrivateKey()
            is java.security.interfaces.ECPrivateKey -> privateKey.toCryptoPrivateKey()
            else -> null
        }
}

internal expect fun getRSAPlatformSignatureInstance(algorithm: RSAAlgorithm, jcaProvider: String?): Signature?
