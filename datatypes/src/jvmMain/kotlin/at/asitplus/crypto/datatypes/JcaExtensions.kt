package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.JwsExtensions.ensureSize
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.JCEECPublicKey
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.math.BigInteger
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec


val JwsAlgorithm.jcaName
    get() = when (this) {
        JwsAlgorithm.ES256 -> "SHA256withECDSA"
        JwsAlgorithm.ES384 -> "SHA384withECDSA"
        JwsAlgorithm.ES512 -> "SHA512withECDSA"
        JwsAlgorithm.HMAC256 -> "HmacSHA256"
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
        RSAPublicKeySpec(BigInteger(1, n), BigInteger.valueOf(e.toLong()))
    ) as RSAPublicKey


fun CryptoPublicKey.Ec.Companion.fromJcaKey(publicKey: ECPublicKey, ecCurve: EcCurve) =
    fromCoordinates(
        ecCurve,
        publicKey.w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes),
        publicKey.w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
    )

fun CryptoPublicKey.Rsa.fromJcaKey(publicKey: RSAPublicKey): CryptoPublicKey.Rsa? {
    val sz = CryptoPublicKey.Rsa.Size.entries.find { it.number.toInt() == publicKey.modulus.bitLength() } ?: return null
    return CryptoPublicKey.Rsa(sz, publicKey.modulus.toByteArray(), publicKey.publicExponent.toInt().toUInt())
}