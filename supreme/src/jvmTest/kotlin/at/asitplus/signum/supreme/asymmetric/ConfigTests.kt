package at.asitplus.signum.supreme.asymmetric

import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.supreme.sign.EphemeralKey
import io.kotest.assertions.throwables.shouldThrow
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import at.asitplus.testballoon.checkAllTests
import at.asitplus.testballoon.checkAllSuites
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.NoSuchProviderException
import java.security.Security
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

val ConfigTests  by testSuite() {
    "Asymmetric Provider Config" {
        val kp =
            EphemeralKey {
                rsa {
                    bits = 2048
                }
            }.getOrThrow()
        val ciphertext =
            AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.encryptorFor(kp.publicKey).encrypt(byteArrayOf(1, 3, 3, 7))
                .getOrThrow()

        shouldThrow<NoSuchProviderException> {
            AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.encryptorFor(kp.publicKey) {
                provider = "IllegalProvider"
            }.encrypt(byteArrayOf(1, 3, 3, 7)).getOrThrow()
        }


        val bcPresent = Security.getProviders().find { it.name == "BC" } != null

        if (bcPresent) Security.removeProvider("BC")
        shouldThrow<NoSuchProviderException> {
            AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.encryptorFor(kp.publicKey) {
                provider = "BC"
            }.encrypt(byteArrayOf(1, 3, 3, 7)).getOrThrow()
        }

        Security.addProvider(BouncyCastleProvider())
        val bcCipherText = AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.encryptorFor(kp.publicKey) {
            provider = "BC"
        }.encrypt(byteArrayOf(1, 3, 3, 7)).getOrThrow()


        if (!bcPresent) Security.removeProvider("BC")

        @OptIn(SecretExposure::class)
        AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.decryptorFor(kp.exportPrivateKey().getOrThrow())
            .decrypt(ciphertext).getOrThrow() shouldBe byteArrayOf(1, 3, 3, 7)
        @OptIn(SecretExposure::class)
        AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.decryptorFor(kp.exportPrivateKey().getOrThrow())
            .decrypt(bcCipherText).getOrThrow() shouldBe byteArrayOf(1, 3, 3, 7)



        shouldThrow<NoSuchProviderException> {
            @OptIn(SecretExposure::class)
            AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.decryptorFor(kp.exportPrivateKey().getOrThrow()) {
                provider = "IllegalProvider"
            }.decrypt(ciphertext).getOrThrow()
        }

        if (bcPresent) Security.removeProvider("BC")
        shouldThrow<NoSuchProviderException> {
            @OptIn(SecretExposure::class)
            AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.decryptorFor(kp.exportPrivateKey().getOrThrow())
            { provider = "BC" }.decrypt(ciphertext).getOrThrow() shouldBe byteArrayOf(1, 3, 3, 7)
        }

        Security.addProvider(BouncyCastleProvider())
        @OptIn(SecretExposure::class)
        AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.decryptorFor(kp.exportPrivateKey().getOrThrow())
        { provider = "BC" }.decrypt(ciphertext).getOrThrow() shouldBe byteArrayOf(1, 3, 3, 7)
        @OptIn(SecretExposure::class)
        AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.decryptorFor(kp.exportPrivateKey().getOrThrow())
        { provider = "BC" }.decrypt(bcCipherText).getOrThrow() shouldBe byteArrayOf(1, 3, 3, 7)


        if (!bcPresent) Security.removeProvider("BC")

    }
}