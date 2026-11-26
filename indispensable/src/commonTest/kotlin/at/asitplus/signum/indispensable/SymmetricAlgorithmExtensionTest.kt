package at.asitplus.signum.indispensable

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

private object ExternalSymmetricAlgorithm :
    SymmetricEncryptionAlgorithm<AuthCapability.AuthenticatedIntegrated, NonceTrait.Required> {
    override val authCapability = AuthCapability.authenticatedIntegrated
    override val nonceTrait = NonceTrait.required
    override val requiredNonceSize = 96.bit
    override val authenticationTagSize = 128.bit
    override val keySize = 128.bit
    override val name = "External test algorithm"
    override val oid = ObjectIdentifier("1.3.6.1.4.1.55555.1")
    override fun toString() = name
}

val SymmetricAlgorithmExtensionTest by matrixSuite {
    "external algorithms can make standard boxes and be neither marker type" {
        ExternalSymmetricAlgorithm.isBlockCipher shouldBe false
        ExternalSymmetricAlgorithm.isStreamCipher shouldBe false

        val box = ExternalSymmetricAlgorithm.sealedBox
            .withNonce(ByteArray(12))
            .from(byteArrayOf(1), ByteArray(16))
        box.algorithm shouldBe ExternalSymmetricAlgorithm
        box.encryptedData.contentEquals(byteArrayOf(1)) shouldBe true
        box.authTag.size shouldBe 16
    }
}
