package at.asitplus.crypto.datatypes

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.asn1.ensureSize
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.sec.SECObjectIdentifiers

val EcCurve.bouncyCastleCurve: org.bouncycastle.math.ec.ECCurve
    get() = when (this) {
        EcCurve.SECP_256_R_1 -> SECNamedCurves.getByOID(SECObjectIdentifiers.secp256r1)
        EcCurve.SECP_384_R_1 -> SECNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
        EcCurve.SECP_521_R_1 -> SECNamedCurves.getByOID(SECObjectIdentifiers.secp521r1)
    }.curve

fun EcCurve.Companion.fromBouncyCastleCurve(curve: org.bouncycastle.math.ec.ECCurve): KmmResult<EcCurve> =
    runCatching {
        EcCurve.entries.firstOrNull { it.bouncyCastleCurve == curve } ?:
            throw IllegalArgumentException("Unsupported curve")
    }.wrap()

val CryptoPublicKey.Ec.bouncyCastlePublicPoint
    get() = curve.bouncyCastleCurve.createPoint(
        java.math.BigInteger(1, x.ensureSize(curve.coordinateLengthBytes)),
        java.math.BigInteger(1, y.ensureSize(curve.coordinateLengthBytes)))

fun CryptoPublicKey.Ec.Companion.fromBouncyCastlePublicPoint(p: org.bouncycastle.math.ec.ECPoint) =
    p.normalize().let { pN ->
        EcCurve.fromBouncyCastleCurve(pN.curve).map { c ->
            CryptoPublicKey.Ec(c, pN.affineXCoord.encoded, pN.affineYCoord.encoded)
        }
    }
