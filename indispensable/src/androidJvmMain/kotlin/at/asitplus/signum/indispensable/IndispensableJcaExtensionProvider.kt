package at.asitplus.signum.indispensable

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.JCAProviderRef
import at.asitplus.signum.dsl.JCAProviderRefO
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.internals.ImplementationError
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.JCEECPublicKey
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.security.*
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.PKCS8EncodedKeySpec
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
            PrivateKey.fromAsn1(privateKey.encoded) as? PrivateKey.WithPublicKey
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
    override fun curveForJcaName(name: String): ShortWeierstrassCurve? =
        ECCurve.entries.find { jcaNameForCurve(it) == name }

    override fun jcaNameForCurve(curve: ECCurve): String? = when {
        curve === ECCurve.SECP_256_R_1 -> "secp256r1"
        curve === ECCurve.SECP_384_R_1 -> "secp384r1"
        curve === ECCurve.SECP_521_R_1 -> "secp521r1"
        else -> null
    }

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
        is EcdsaAlgorithm -> if (algorithm.requiredCurve?.isBuiltIn == false) null else when (val digest = algorithm.digest) {
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
            if (algorithm.requiredCurve?.isBuiltIn == false) null else sigGetInstance("NONEwithECDSA", jcaProviderRef)
        else -> null
    }

    override fun parseJCASignatureBytes(algorithm: SignatureAlgorithm, sigBytes: ByteArray): Signature? = when (algorithm) {
        is EcdsaAlgorithm ->
            if (algorithm.requiredCurve?.isBuiltIn == false) null else EcdsaSignature.fromRawSignatureValue(sigBytes)
        is RsaAlgorithm -> RsaSignature.fromRawSignatureValue(sigBytes)
        else -> null
    }

    override fun getJCASignatureBytes(signature: Signature): ByteArray? = when (signature) {
        is EcdsaSignature, is RsaSignature -> signature.asn1.toRepresentation().rawBytes
        else -> null
    }

    override fun publicKeyToJcaPublicKey(publicKey: PublicKey) = when(publicKey) {
        is EcdsaPublicKey -> if (publicKey.curve.isBuiltIn) publicKey.toBuiltInJcaPublicKey() else null
        is RsaPublicKey -> publicKey.toJcaPublicKey()
        else -> null
    }

    override fun jcaPublicKeyToPublicKey(publicKey: JCAPublicKey) = when(publicKey) {
        is java.security.interfaces.RSAPublicKey -> publicKey.toPublicKey()
        is ECPublicKey -> publicKey.toBuiltInPublicKey()
        else -> null
    }

    override fun privateKeyToJcaPrivateKey(privateKey: PrivateKey) =
        when (privateKey) {
            is RsaPrivateKey -> privateKey.toJcaPrivateKey()
            is EcdsaPrivateKey.WithPublicKey -> if (privateKey.curve.isBuiltIn) privateKey.toBuiltInJcaPrivateKey() else null
            is EcdsaPrivateKey.WithoutPublicKey -> privateKey.toBuiltInJcaPrivateKey()
            else -> null
        }

    override fun jcaPrivateKeyToPrivateKey(privateKey: JCAPrivateKey) =
        when (privateKey) {
            is java.security.interfaces.RSAPrivateKey -> privateKey.toPrivateKey()
            is ECPrivateKey -> privateKey.toBuiltInPrivateKey()
            else -> null
        }

    private fun EcdsaPublicKey.toBuiltInJcaPublicKey(): ECPublicKey {
        val parameterSpec = ECNamedCurveTable.getParameterSpec(curve.jwkName)
        val point = parameterSpec.curve.createPoint(x.residue.toJavaBigInteger(), y.residue.toJavaBigInteger())
        return JCEECPublicKey("EC", ECPublicKeySpec(point, parameterSpec))
    }

    private fun ECPublicKey.toBuiltInPublicKey(): EcdsaPublicKey {
        val spki = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(encoded))
        val curveOid = spki.algorithm.parameters as? ASN1ObjectIdentifier
            ?: throw UnsupportedCryptoException("Expected a named JCA EC curve")
        val oid = ObjectIdentifier(curveOid.id)
        val curve = ECCurve.entries.find { it.oid == oid }
            ?: throw UnsupportedCryptoException("Unsupported JCA EC curve $curveOid")
        return EcdsaPublicKey.fromUncompressed(curve, w.affineX.toByteArray(), w.affineY.toByteArray())
    }

    private fun EcdsaPrivateKey.toBuiltInJcaPrivateKey(): ECPrivateKey =
        KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(asn1.toDer())) as ECPrivateKey

    private fun ECPrivateKey.toBuiltInPrivateKey(): EcdsaPrivateKey.WithPublicKey =
        EcdsaPrivateKey.fromAsn1(encoded) as? EcdsaPrivateKey.WithPublicKey
            ?: throw UnsupportedCryptoException("Missing named curve in JCA EC private key")
}
