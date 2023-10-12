package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.ensureSize
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.JCEECPublicKey
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec


val JwsAlgorithm.jcaName
    get() = when (this) {
        JwsAlgorithm.ES256 -> "SHA256withECDSA"
        JwsAlgorithm.ES384 -> "SHA384withECDSA"
        JwsAlgorithm.ES512 -> "SHA512withECDSA"
        JwsAlgorithm.HMAC256 -> "HmacSHA256"
        JwsAlgorithm.RS256 -> "SHA256withRSA"
        JwsAlgorithm.RS384 -> "SHA348withRSA"
        JwsAlgorithm.RS512 -> "SHA512withRSA"
        JwsAlgorithm.UNOFFICIAL_RSA_SHA1 -> "SHA1withRSA"
    }

val Digest.jcaName
    get() = when (this) {
        Digest.SHA256 -> "SHA-256"
    }

val EcCurve.jcaName
    get() = when (this) {
        EcCurve.SECP_256_R_1 -> "secp256r1"
        EcCurve.SECP_384_R_1 -> "secp384r1"
        EcCurve.SECP_521_R_1 -> "secp521r1"
    }

fun EcCurve.Companion.byJcaName(name: String) = EcCurve.entries.find { it.jcaName == name }


fun CryptoPublicKey.getPublicKey() = when(this) {
    is CryptoPublicKey.Ec -> getPublicKey()
    is CryptoPublicKey.Rsa -> getPublicKey()
}

fun CryptoPublicKey.Ec.getPublicKey(): ECPublicKey {
    val parameterSpec = ECNamedCurveTable.getParameterSpec(curve.jwkName)
    val x = BigInteger(1, x)
    val y = BigInteger(1, y)
    val ecPoint = parameterSpec.curve.createPoint(x, y)
    val ecPublicKeySpec = ECPublicKeySpec(ecPoint, parameterSpec)
    return JCEECPublicKey("EC", ecPublicKeySpec)
}

private val rsaFactory = KeyFactory.getInstance("RSA")
fun CryptoPublicKey.Rsa.getPublicKey(): RSAPublicKey =
    rsaFactory.generatePublic(
        RSAPublicKeySpec(BigInteger(1, n), BigInteger(e))
    ) as RSAPublicKey


fun CryptoPublicKey.Ec.Companion.fromJcaKey(publicKey: ECPublicKey): CryptoPublicKey.Ec? {
    val curve = EcCurve.byJcaName(
        SECNamedCurves.getName(
            SubjectPublicKeyInfo.getInstance(
                ASN1Sequence.getInstance(publicKey.encoded)
            ).algorithm.parameters as ASN1ObjectIdentifier
        )
    ) ?: return null
    return fromCoordinates(
        curve,
        publicKey.w.affineX.toByteArray().ensureSize(curve.coordinateLengthBytes),
        publicKey.w.affineY.toByteArray().ensureSize(curve.coordinateLengthBytes)
    )
}

fun CryptoPublicKey.Companion.fromJcaKey(publicKey: PublicKey) =
    if (publicKey is RSAPublicKey) CryptoPublicKey.Rsa.fromJcaKey(publicKey)
    else if (publicKey is ECPublicKey) CryptoPublicKey.Ec.fromJcaKey(publicKey)
    else throw IllegalArgumentException("Unsupported Key Type")


fun CryptoPublicKey.Rsa.Companion.fromJcaKey(publicKey: RSAPublicKey): CryptoPublicKey.Rsa? {
    return CryptoPublicKey.Rsa(publicKey.modulus.toByteArray(), publicKey.publicExponent.toByteArray())
}