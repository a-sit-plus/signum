package at.asitplus.signum.indispensable

import at.asitplus.signum.dsl.JCAProviderRef
import at.asitplus.signum.dsl.JCAProviderRefO
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.internals.ImplementationError
import java.security.*
import java.security.PrivateKey as JCAPrivateKey
import java.security.PublicKey as JCAPublicKey
import java.security.Signature as JCASignature

/** This is not semantics-aware, but allows fallback for public key/private key parsing based on DER formats */
object FallbackToDERFormat : JcaMappingProvider {
    override fun jcaPublicKeyToPublicKey(publicKey: JCAPublicKey): PublicKey? =
        if (publicKey.format?.equals("X.509", ignoreCase = true) == true)
            PublicKey.fromAsn1(publicKey.encoded)
        else null

    override fun jcaPrivateKeyToPrivateKey(privateKey: JCAPrivateKey): PrivateKey.WithPublicKey? =
        if (privateKey.format?.equals("PKCS#8", ignoreCase = true) == true)
            PrivateKey.fromAsn1(privateKey.encoded) as PrivateKey.WithPublicKey
        else null
}

private fun sigGetInstance(alg: String, provider: JCAProviderRef): JCASignature =
    when (provider) {
        is JCAProviderRef.ByName -> JCASignature.getInstance(alg, provider.provider)
        is JCAProviderRefO -> JCASignature.getInstance(alg, provider.provider)
        is JCAProviderRef.None -> JCASignature.getInstance(alg)
        else -> throw ImplementationError("invalid JCAProvider ref")
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

    override fun parseJCASignatureBytes(algorithm: SignatureAlgorithm, sigBytes: ByteArray): Signature? = when (algorithm) {
        is EcdsaAlgorithm -> EcdsaSignature.fromRawSignatureValue(sigBytes)
        is RsaAlgorithm -> RsaSignature.fromRawSignatureValue(sigBytes)
        else -> null
    }

    override fun getJCASignatureBytes(signature: Signature): ByteArray? = when (signature) {
        is EcdsaSignature, is RsaSignature -> signature.asn1.toRepresentation().rawBytes
        else -> null
    }

    override fun publicKeyToJcaPublicKey(publicKey: PublicKey) = when(publicKey) {
        is EcdsaPublicKey -> publicKey.toJcaPublicKey()
        is RsaPublicKey -> publicKey.toJcaPublicKey()
        else -> null
    }

    override fun jcaPublicKeyToPublicKey(publicKey: JCAPublicKey) = when(publicKey) {
        is java.security.interfaces.RSAPublicKey -> publicKey.toPublicKey()
        is java.security.interfaces.ECPublicKey -> publicKey.toPublicKey()
        else -> null
    }

    override fun privateKeyToJcaPrivateKey(privateKey: PrivateKey) =
        when (privateKey) {
            is RsaPrivateKey -> privateKey.toJcaPrivateKey()
            is EcdsaPrivateKey -> privateKey.toJcaPrivateKey()
            else -> null
        }

    override fun jcaPrivateKeyToPrivateKey(privateKey: JCAPrivateKey) =
        when (privateKey) {
            is java.security.interfaces.RSAPrivateKey -> privateKey.toPrivateKey()
            is java.security.interfaces.ECPrivateKey -> privateKey.toPrivateKey()
            else -> null
        }
}
