package at.asitplus.signum.supreme.symmetric

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.engine.runBlocking

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

val SymmetricExtensionRejectionTest by matrixSuite {
    "Supreme declines external algorithms and opaque keys" {
        val externalKey = ExternalSymmetricAlgorithm.keyFrom(ByteArray(16))
        shouldThrow<UnsupportedCryptoException> {
            runBlocking { externalKey.encrypt(byteArrayOf(1)) }
        }

        val opaqueKey = object : SymmetricKey<SymmetricEncryptionAlgorithm.ChaCha20Poly1305> {
            override val algorithm = SymmetricEncryptionAlgorithm.ChaCha20Poly1305
            override val additionalProperties = mutableMapOf<String, String>()
        }
        shouldThrow<UnsupportedCryptoException> {
            runBlocking { opaqueKey.encrypt(byteArrayOf(1)) }
        }
    }
}
