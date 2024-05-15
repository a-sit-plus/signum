import at.asitplus.crypto.datatypes.*
import at.asitplus.crypto.datatypes.asn1.ensureSize
import at.asitplus.crypto.datatypes.asn1.stripLeadingSignByte
import at.asitplus.crypto.datatypes.misc.SIGNUM_NEGATIVE
import at.asitplus.crypto.datatypes.misc.SIGNUM_POSITIVE
import at.asitplus.crypto.datatypes.misc.decompressY
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.sec.SECObjectIdentifiers
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.math.BigInteger
import java.security.*
import java.security.interfaces.ECPrivateKey

private fun BigInteger.toUnsignedByteArray(): ByteArray =
    also { require(signum() == 1) }.toByteArray().stripLeadingSignByte()

class BouncyCastleTest : FreeSpec({
    Security.addProvider(BouncyCastleProvider())
    "BouncyCastle decoding" {
        val curve = EcCurve.SECP_256_R_1
        val xBytes = byteArrayOf(0x05).ensureSize(32u)
        val point = curve.bouncyCastleCurve.decodePoint(byteArrayOf(0x02) + xBytes)
        val key = CryptoPublicKey.Ec.fromBouncyCastlePublicPoint(point).getOrThrow()
        key.curve shouldBe EcCurve.SECP_256_R_1
        key.x shouldBe xBytes
        key.y shouldBe decompressY(curve, xBytes, SIGNUM_NEGATIVE)
    }
    "BouncyCastle encoding" {
        val curve = EcCurve.SECP_384_R_1
        val xBytes = byteArrayOf(0x0a).ensureSize(48u)
        val key = CryptoPublicKey.Ec(curve, xBytes, SIGNUM_POSITIVE)
        val point = key.bouncyCastlePublicPoint
        point.curve shouldBe SECNamedCurves.getByOID(SECObjectIdentifiers.secp384r1).curve
        point.affineXCoord.encoded shouldBe xBytes
        point.affineYCoord.encoded shouldBe key.y
    }
    "Generator validity test" {
        for (curve in EcCurve.entries) {
            val keyPair = KeyPairGenerator.getInstance("ECDSA", "BC").run {
                initialize(ECNamedCurveTable.getParameterSpec(curve.oid.toString()))
                generateKeyPair()
            }
            val publicKey = CryptoPublicKey.fromJcaPublicKey(keyPair.public).getOrThrow() as CryptoPublicKey.Ec
            val privateKey = (keyPair.private as ECPrivateKey).s

            publicKey.curve shouldBe curve

            publicKey.bouncyCastlePublicPoint shouldBe
                publicKey.curve.generator.bouncyCastlePublicPoint.multiply(privateKey)
        }
    }
    "SplitECDSA test".config(
        invocations = 512
    ) {
        val rng = SecureRandom.getInstanceStrong()
        val jcaKeyPair = KeyPairGenerator.getInstance("ECDSA", "BC").run {
            initialize(ECNamedCurveTable.getParameterSpec(SECObjectIdentifiers.secp256r1.id), rng)
            generateKeyPair()
        }
        val ourPublicKey = CryptoPublicKey.fromJcaPublicKey(jcaKeyPair.public).getOrThrow() as CryptoPublicKey.Ec
        val curve = ourPublicKey.curve
        val bcPublicKey = ourPublicKey.bouncyCastlePublicPoint

        val blind = run {
            generateSequence {
                BigInteger(1, ByteArray(curve.coordinateLengthBytes.toInt()).also { rng.nextBytes(it) })
            }.first { (BigInteger.ZERO < it) && (it < curve.order.toJavaBigInteger()) }
        }
        val blindInv = blind.modInverse(curve.order.toJavaBigInteger())

        val derivedPublicKey = CryptoPublicKey.Ec.fromBouncyCastlePublicPoint(
                bcPublicKey.multiply(blind))
            .transform(CryptoPublicKey.Ec::getJcaPublicKey).getOrThrow()

        val data = ByteArray(32).also { rng.nextBytes(it) }
        val dataHash = MessageDigest.getInstance("SHA-256","BC").digest(data)
        val massagedDataHash = BigInteger(1, dataHash)
            .multiply(blindInv)
            .mod(curve.order.toJavaBigInteger())
            .toUnsignedByteArray()
        val jcaSignature = Signature.getInstance("NONEwithECDSA", "BC").run {
            initSign(jcaKeyPair.private)
            update(massagedDataHash)
            sign()
        }
        val ourSignature = CryptoSignature.decodeFromDer(jcaSignature) as CryptoSignature.EC
        val massagedS = BigInteger(1, ourSignature.s)
            .multiply(blind)
            .mod(curve.order.toJavaBigInteger())
            .toUnsignedByteArray()
        val massagedSignature = CryptoSignature.EC(ourSignature.r, massagedS).encodeToDer()

        Signature.getInstance("SHA256withECDSA", "BC").run {
            initVerify(derivedPublicKey)
            update(data)
            verify(massagedSignature)
        } shouldBe true
    }
})
