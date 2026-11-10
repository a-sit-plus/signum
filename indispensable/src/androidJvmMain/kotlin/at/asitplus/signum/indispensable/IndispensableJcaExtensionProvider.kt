package at.asitplus.signum.indispensable

import at.asitplus.signum.dsl.JCAProviderRef
import at.asitplus.signum.dsl.JCAProviderRefO
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.internals.ImplementationError
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey

/** This is not semantics-aware, but allows fallback for public key/private key parsing based on DER formats */
object FallbackToDERFormat : JcaMappingProvider {
    override fun jcaPublicKeyToCryptoPublicKey(publicKey: PublicKey): CryptoPublicKey? =
        if (publicKey.format?.equals("X.509", ignoreCase = true) == true)
            CryptoPublicKey.fromAsn1(publicKey.encoded)
        else null

    override fun jcaPrivateKeyToCryptoPrivateKey(privateKey: PrivateKey): CryptoPrivateKey.WithPublicKey? =
        if (privateKey.format?.equals("PKCS#8", ignoreCase = true) == true)
            CryptoPrivateKey.fromAsn1(privateKey.encoded) as CryptoPrivateKey.WithPublicKey
        else null
}

/** This provides semantics-aware operations for types supported by Indispensable */
object IndispensableJcaExtensionProvider : JcaMappingProvider {
    override fun getJCAMessageDigestInstance(digest: Digest, jcaProviderRef: JCAProviderRef): MessageDigest? {
        if (digest !is WellKnownDigest) return null
        return when (jcaProviderRef) {
            is JCAProviderRef.ByName -> MessageDigest.getInstance(digest.jcaName, jcaProviderRef.provider)
            is JCAProviderRefO -> MessageDigest.getInstance(digest.jcaName, jcaProviderRef.provider)
            is JCAProviderRef.None -> MessageDigest.getInstance(digest.jcaName)
            else -> throw ImplementationError("invalid JCAProvider ref")
        }
    }

    override fun getJCASignatureInstance(algorithm: SignatureAlgorithm, jcaProviderRef: JCAProviderRef) = when (algorithm) {
        is EcdsaAlgorithm -> when (val digest = algorithm.digest) {
            is WellKnownDigest? -> sigGetInstance("${digest.jcaAlgorithmComponent}withECDSA", jcaProviderRef)
            else -> null
        }
        is RsaAlgorithm -> when (val params = algorithm.parameters) {
            is RsaAlgorithm.Parameters.Pkcs1Padded -> when (val digest = params.digest) {
                is WellKnownDigest -> sigGetInstance("${digest.jcaAlgorithmComponent}withRSA", jcaProviderRef)
                else -> null
            }

            is RsaAlgorithm.Parameters.PssPadded -> {
                val jcaParams = params.jcaPSSParams
                try {
                    sigGetInstance("RSASSA-PSS", jcaProviderRef)
                } catch (x: NoSuchAlgorithmException) {
                    try {
                        sigGetInstance("${(params.digest as WellKnownDigest).jcaAlgorithmComponent}withRSA/PSS", jcaProviderRef)
                    } catch (x2: NoSuchAlgorithmException) {
                        throw NoSuchAlgorithmException("${x.message}; ${x2.message}.")
                    }
                }.also { it.setParameter(jcaParams) }
            }
        }
        else -> null
    }

    override fun getJCASignatureInstancePreHashed(algorithm: SignatureAlgorithm, jcaProviderRef: JCAProviderRef) = when (algorithm) {
        is EcdsaAlgorithm ->
            sigGetInstance("NONEwithECDSA", jcaProviderRef)
        else -> null
    }

    override fun parseJCASignatureBytes(algorithm: SignatureAlgorithm, sigBytes: ByteArray): CryptoSignature? = when (algorithm) {
        is EcdsaAlgorithm -> EcdsaSignature.fromRawSignatureValue(sigBytes)
        is RsaAlgorithm -> RsaSignature.fromRawSignatureValue(sigBytes)
        else -> null
    }

    override fun getJCASignatureBytes(signature: CryptoSignature): ByteArray? = when (signature) {
        is EcdsaSignature, is RsaSignature -> signature.toAsn1().rawBytes
        else -> null
    }

    override fun cryptoPublicKeyToJcaPublicKey(publicKey: CryptoPublicKey) = when(publicKey) {
        is EcdsaPublicKey -> publicKey.toJcaPublicKey()
        is RsaPublicKey -> publicKey.toJcaPublicKey()
        else -> null
    }

    override fun jcaPublicKeyToCryptoPublicKey(publicKey: PublicKey) = when(publicKey) {
        is java.security.interfaces.RSAPublicKey -> publicKey.toCryptoPublicKey()
        is java.security.interfaces.ECPublicKey -> publicKey.toCryptoPublicKey()
        else -> null
    }

    override fun cryptoPrivateKeyToJcaPrivateKey(privateKey: CryptoPrivateKey) =
        when (privateKey) {
            is RsaPrivateKey -> privateKey.toJcaPrivateKey()
            is EcdsaPrivateKey -> privateKey.toJcaPrivateKey()
            else -> null
        }

    override fun jcaPrivateKeyToCryptoPrivateKey(privateKey: PrivateKey) =
        when (privateKey) {
            is java.security.interfaces.RSAPrivateKey -> privateKey.toCryptoPrivateKey()
            is java.security.interfaces.ECPrivateKey -> privateKey.toCryptoPrivateKey()
            else -> null
        }
}
