package at.asitplus.signum.examples

import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

val CoreExamples by matrixSuite {
    "public key DER, PEM and JCA roundtrip" {
        // --8<-- [start:core-key-roundtrip]
        val jca = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair().public
        val publicKey = jca.toCryptoPublicKey()
        val der = Signum.Der.encodeToByteArray<CryptoPublicKey>(publicKey)
        val decoded = Signum.Der.decodeFromByteArray<CryptoPublicKey>(der) /* (1)! */
        decoded shouldBe publicKey
        Signum.Der.decodeFromPem<CryptoPublicKey>(Signum.Der.encodeToPem(publicKey)) shouldBe publicKey
        decoded.toJcaPublicKey().encoded.contentEquals(jca.encoded) shouldBe true
        // --8<-- [end:core-key-roundtrip]
    }
    "ECDSA signature representations" {
        // --8<-- [start:core-signature-formats]
        val p1363 = ByteArray(64).apply { this[31] = 1; this[63] = 2 }
        val signature = EcdsaSignature.fromP1363Bytes(ECCurve.SECP_256_R_1, p1363)
        signature.joseBytes.contentEquals(p1363) shouldBe true
        signature.coseBytes.contentEquals(p1363) shouldBe true
        signature.joseBytes.size shouldBe 64
        // --8<-- [end:core-signature-formats]
    }
}
