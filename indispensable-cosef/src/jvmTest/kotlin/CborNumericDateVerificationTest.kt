import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.cosef.CborWebToken
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.getJCASignatureInstance
import at.asitplus.signum.indispensable.jcaSignatureBytes
import at.asitplus.signum.indispensable.parseJCASignature
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.time.Instant

private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

/** CBOR byte string header for lengths < 256 */
private fun ByteArray.byteString(): ByteArray = when {
    size < 24 -> bytes(0x40 + size)
    else -> bytes(0x58, size)
} + this

val CborNumericDateVerificationTest by matrixSuite {

    "COSE_Sign1 with a CWT containing float NumericDates decodes, verifies and round-trips" {
        val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        // {1: -7 (ES256)}
        val protectedHeader = bytes(0xA1, 0x01, 0x26)
        // {4: 1700000000.5 (float64), 6: 1.0 (float16)}
        val payload = bytes(0xA2, 0x04, 0xFB) +
                ByteArray(8) { (1700000000.5.toRawBits() shr (8 * (7 - it))).toByte() } +
                bytes(0x06, 0xF9, 0x3C, 0x00)
        val sigStructure = bytes(0x84, 0x6A) + "Signature1".encodeToByteArray() +
                protectedHeader.byteString() + byteArrayOf().byteString() + payload.byteString()
        val algorithm = CoseAlgorithm.Signature.ES256.algorithm
        val signature = algorithm.getJCASignatureInstance().run {
            initSign(keyPair.private)
            update(sigStructure)
            (algorithm.parseJCASignature(sign()) as EcdsaSignature.IndefiniteLength).withCurve(ECCurve.SECP_256_R_1)
        }
        val input = bytes(0x84) + protectedHeader.byteString() + bytes(0xA0) + payload.byteString() +
                signature.coseBytes.byteString()

        val cose = CoseSigned.deserialize(CborWebToken.serializer(), input).getOrThrow()

        cose.payload?.expiration shouldBe Instant.fromEpochSeconds(1700000000, 500_000_000)
        cose.payload?.issuedAt shouldBe Instant.fromEpochSeconds(1)
        cose.prepareCoseSignatureInput() shouldBe sigStructure
        algorithm.getJCASignatureInstance().run {
            initVerify(keyPair.public)
            update(cose.prepareCoseSignatureInput())
            verify(cose.signature.jcaSignatureBytes)
        } shouldBe true
        cose.serialize(CborWebToken.serializer()) shouldBe input
    }
}
