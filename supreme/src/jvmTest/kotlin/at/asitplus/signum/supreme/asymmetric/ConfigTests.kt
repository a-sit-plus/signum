package at.asitplus.signum.supreme.asymmetric

import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.asymmetric.RSAPadding
import at.asitplus.signum.UnsupportedCryptoException
import io.kotest.assertions.throwables.shouldThrow
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.NoSuchProviderException
import java.security.Security

val ConfigTests  by matrixSuite {
    "External asymmetric algorithms are rejected before key validation" {
        val externalAlgorithm = object : AsymmetricEncryptionAlgorithm {
            override val oid = AsymmetricEncryptionAlgorithm.RSA.oid
        }
        val ecSigner = Signer.Ephemeral { ec {} }
        @OptIn(SecretExposure::class)
        val ecPrivateKey = ecSigner.exportPrivateKey()

        shouldThrow<UnsupportedCryptoException> {
            externalAlgorithm.encryptorFor(ecSigner.publicKey)
        }
        shouldThrow<UnsupportedCryptoException> {
            externalAlgorithm.decryptorFor(ecPrivateKey)
        }
    }

    "All exposed RSA padding variants round trip" {
        val kp = Signer.Ephemeral { rsa { bits = 2048 } }
        val plaintext = byteArrayOf(1, 3, 3, 7)
        @OptIn(at.asitplus.signum.HazardousMaterials::class)
        val paddings = listOf(
            RSAPadding.NONE,
            RSAPadding.PKCS1,
            RSAPadding.OAEP.SHA1,
            RSAPadding.OAEP.SHA256,
            RSAPadding.OAEP.SHA384,
            RSAPadding.OAEP.SHA512
        )
        paddings.forEach { padding ->
            val algorithm = AsymmetricEncryptionAlgorithm.RSA(padding)
            val ciphertext = algorithm.encryptorFor(kp.publicKey).encrypt(plaintext)
            @OptIn(SecretExposure::class)
            val privateKey = kp.exportPrivateKey()
            algorithm.decryptorFor(privateKey).decrypt(ciphertext) shouldBe plaintext
        }
    }

    "Asymmetric Provider Config" {
        val kp =
            Signer.Ephemeral {
                rsa {
                    bits = 2048
                }
            }
        val ciphertext =
            AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.encryptorFor(kp.publicKey).encrypt(byteArrayOf(1, 3, 3, 7))

        shouldThrow<NoSuchProviderException> {
            AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.encryptorFor(kp.publicKey) {
                provider = "IllegalProvider"
            }.encrypt(byteArrayOf(1, 3, 3, 7))
        }


        val bcPresent = Security.getProviders().find { it.name == "BC" } != null

        if (bcPresent) Security.removeProvider("BC")
        shouldThrow<NoSuchProviderException> {
            AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.encryptorFor(kp.publicKey) {
                provider = "BC"
            }.encrypt(byteArrayOf(1, 3, 3, 7))
        }

        Security.addProvider(BouncyCastleProvider())
        val bcCipherText = AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.encryptorFor(kp.publicKey) {
            provider = "BC"
        }.encrypt(byteArrayOf(1, 3, 3, 7))


        if (!bcPresent) Security.removeProvider("BC")

        @OptIn(SecretExposure::class)
        AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.decryptorFor(kp.exportPrivateKey())
            .decrypt(ciphertext) shouldBe byteArrayOf(1, 3, 3, 7)
        @OptIn(SecretExposure::class)
        AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.decryptorFor(kp.exportPrivateKey())
            .decrypt(bcCipherText) shouldBe byteArrayOf(1, 3, 3, 7)



        shouldThrow<NoSuchProviderException> {
            @OptIn(SecretExposure::class)
            AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.decryptorFor(kp.exportPrivateKey()) {
                provider = "IllegalProvider"
            }.decrypt(ciphertext)
        }

        if (bcPresent) Security.removeProvider("BC")
        shouldThrow<NoSuchProviderException> {
            @OptIn(SecretExposure::class)
            AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.decryptorFor(kp.exportPrivateKey())
            { provider = "BC" }.decrypt(ciphertext) shouldBe byteArrayOf(1, 3, 3, 7)
        }

        Security.addProvider(BouncyCastleProvider())
        @OptIn(SecretExposure::class)
        AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.decryptorFor(kp.exportPrivateKey())
        { provider = "BC" }.decrypt(ciphertext) shouldBe byteArrayOf(1, 3, 3, 7)
        @OptIn(SecretExposure::class)
        AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.decryptorFor(kp.exportPrivateKey())
        { provider = "BC" }.decrypt(bcCipherText) shouldBe byteArrayOf(1, 3, 3, 7)


        if (!bcPresent) Security.removeProvider("BC")

    }
}
