package at.asitplus.signum.indispensable

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.SignatureAlgorithmIdentifier
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.asymmetric.RsaEncryptionAlgorithm
import at.asitplus.signum.indispensable.asymmetric.RSAPadding as AsymmetricRsaPadding
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.symmetric.AuthCapability
import at.asitplus.signum.indispensable.symmetric.KeyType
import at.asitplus.signum.indispensable.symmetric.NonceTrait
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val AlgorithmRegistryTest by testSuite {
    "built-in algorithms populate the registry on first access" {
        AlgorithmRegistry.signatureAlgorithms.map { it.toString() }.shouldContain("ECDSAwithSHA256")
        AlgorithmRegistry.messageAuthenticationCodes.map { it.toString() }.shouldContain("HmacSha256")
        AlgorithmRegistry.asymmetricEncryptionAlgorithms.map { it.toString() }.shouldContain("RSA(PKCS1)")
        AlgorithmRegistry.symmetricEncryptionAlgorithms.map { it.name }.shouldContain("ChaCha20-Poly1305")
    }

    "custom signature algorithms can be registered" {
        val custom = object : SignatureAlgorithm {
            override fun toString() = "CustomSignatureAlgorithm"
        }

        SignatureAlgorithm.register(custom)

        SignatureAlgorithm.entries.shouldContain(custom)
        DataIntegrityAlgorithm.entries.shouldContain(custom)
    }

    "custom MAC algorithms can be registered" {
        val custom = object : MessageAuthenticationCode {
            override val outputLength = 128.bit
            override fun toString() = "CustomMacAlgorithm"
        }

        AlgorithmRegistry.registerMessageAuthenticationCode(custom)

        MessageAuthenticationCode.entries.shouldContain(custom)
        DataIntegrityAlgorithm.entries.shouldContain(custom)
    }

    "custom symmetric encryption algorithms can be registered" {
        val custom =
            object : SymmetricEncryptionAlgorithm.Unauthenticated<NonceTrait.Without>,
                SymmetricEncryptionAlgorithm.WithoutNonce<AuthCapability.Unauthenticated, KeyType.Integrated> {
                override val oid = ObjectIdentifier("1.3.6.1.4.1.55555.1")
                override val name = "CustomSymmetricAlgorithm"
                override val keySize = 128.bit
                override fun toString() = name
            }

        AlgorithmRegistry.registerSymmetricEncryptionAlgorithm(custom)

        SymmetricEncryptionAlgorithm.entries.shouldContain(custom)
    }

    "custom asymmetric algorithms can be registered" {
        val customPadding = object : AsymmetricRsaPadding {
            override fun toString() = "CUSTOM"
        }
        val customAlgorithm = RsaEncryptionAlgorithm(customPadding)

        AlgorithmRegistry.registerAsymmetricRsaPadding(customPadding)
        AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(customAlgorithm)

        AlgorithmRegistry.asymmetricRsaPaddings.shouldContain(customPadding)
        AlgorithmRegistry.asymmetricEncryptionAlgorithms.shouldContain(customAlgorithm)
    }

    "custom X.509 signature mappings can be registered explicitly" {
        val raw = SignatureAlgorithmIdentifier(ObjectIdentifier("1.3.6.1.4.1.55555.9.1"), emptyList())
        val algorithm = object : SignatureAlgorithm {
            override fun toString() = "CustomX509SignatureAlgorithm"
        }

        val registered = X509SignatureAlgorithm.register(raw, algorithm)

        AlgorithmRegistry.findSignatureAlgorithm(raw) shouldNotBe null
        AlgorithmRegistry.findX509SignatureIdentifier(algorithm) shouldNotBe null
        registered.raw shouldBe raw
        registered.algorithm shouldBe algorithm
    }
}
