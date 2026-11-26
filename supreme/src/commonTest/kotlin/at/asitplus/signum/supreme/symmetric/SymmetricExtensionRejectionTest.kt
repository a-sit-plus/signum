package at.asitplus.signum.supreme.symmetric

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.supreme.symmetric.discouraged.andPredefinedNonce
import at.asitplus.signum.supreme.symmetric.discouraged.encrypt
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow

private object ExternalSymmetricAlgorithm :
    SymmetricEncryptionAlgorithm<AuthCapability.AuthenticatedIntegrated, NonceTrait.Required> {
    override val authCapability = AuthCapability.authenticatedIntegrated
    override val nonceTrait = NonceTrait.required
    override val requiredNonceSize = 96.bit
    override val authenticationTagSize = 128.bit
    override val keySize = 128.bit
    override val name = "External test algorithm"
    override val oid = ObjectIdentifier("1.3.6.1.4.1.55555.2")
    override fun toString() = name
}

@OptIn(HazardousMaterials::class)
val SymmetricExtensionRejectionTest by matrixSuite {
    "Supreme rejects external algorithms at operation entry points" {
        val externalKey = ExternalSymmetricAlgorithm.keyFrom(ByteArray(16))
        val data = byteArrayOf(1)
        val nonce = ByteArray(12)
        val tag = ByteArray(16)
        val box = ExternalSymmetricAlgorithm.sealedBox.withNonce(nonce).from(data, tag)
        shouldThrow<UnsupportedCryptoException> { externalKey.encrypt(data) }
        shouldThrow<UnsupportedCryptoException> { box.decrypt(externalKey) }
        shouldThrow<UnsupportedCryptoException> {
            externalKey.andPredefinedNonce(nonce).encrypt(data)
        }
    }

    "Supreme rejects opaque wrapping keys" {
        val wrap = SymmetricEncryptionAlgorithm.AES_128.WRAP.RFC3394
        val data = ByteArray(16)
        val opaqueKey = object : SymmetricKey<SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394> {
            override val algorithm = wrap
            override val additionalProperties = mutableMapOf<String, String>()
        }
        shouldThrow<UnsupportedCryptoException> { opaqueKey.encrypt(data) }
        val box = wrap.keyFrom(ByteArray(16)).encrypt(data)
        shouldThrow<UnsupportedCryptoException> { box.decrypt(opaqueKey) }
    }
}
