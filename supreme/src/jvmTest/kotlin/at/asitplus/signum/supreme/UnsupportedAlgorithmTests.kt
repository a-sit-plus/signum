package at.asitplus.signum.supreme

import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.AlgorithmRegistry
import at.asitplus.signum.indispensable.MessageAuthenticationCode
import at.asitplus.signum.indispensable.key.PrivateKey
import at.asitplus.signum.indispensable.key.PublicKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.asymmetric.RsaEncryptionAlgorithm
import at.asitplus.signum.indispensable.asymmetric.RsaEncryptionPadding
import at.asitplus.signum.indispensable.key.RsaPrivateKey
import at.asitplus.signum.indispensable.key.RsaPublicKey
import at.asitplus.signum.indispensable.asymmetric.RSAPadding as AsymmetricRsaPadding
import at.asitplus.signum.supreme.asymmetric.encryptorFor
import at.asitplus.signum.supreme.mac.mac
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.signum.supreme.sign.signerFor
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.types.shouldBeInstanceOf

val UnsupportedAlgorithmTests by testSuite {
    "custom signature algorithm is rejected by signers" {
        @OptIn(SecretExposure::class)
        val privateKey = EphemeralKey {
            rsa {
                bits = 2048
            }
        }.getOrThrow().exportPrivateKey().getOrThrow()

        val custom = object : SignatureAlgorithm {
            override fun toString() = "UnsupportedSignatureAlgorithm"
        }
        SignatureAlgorithm.register(custom)

        custom.signerFor(privateKey as PrivateKey.WithPublicKey<*>)
            .exceptionOrNull()
            .shouldBeInstanceOf<UnsupportedCryptoException>()
    }

    "custom RSA padding is rejected by encryptors" {
        val publicKey = EphemeralKey {
            rsa {
                bits = 2048
            }
        }.getOrThrow().publicKey as RsaPublicKey

        val customPadding = object : RsaEncryptionPadding {
            override fun toString() = "CUSTOM"
        }
        AlgorithmRegistry.registerAsymmetricRsaPadding(customPadding)

        RsaEncryptionAlgorithm(customPadding)
            .encryptorFor(publicKey)
            .encrypt(byteArrayOf(1, 3, 3, 7))
            .exceptionOrNull()
            .shouldBeInstanceOf<UnsupportedCryptoException>()
    }

    "custom MAC algorithm is rejected" {
        val custom = object : MessageAuthenticationCode {
            override val outputLength = 128.bit
            override fun toString() = "UnsupportedMacAlgorithm"
        }
        AlgorithmRegistry.registerMessageAuthenticationCode(custom)

        custom.mac(byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6))
            .exceptionOrNull()
            .shouldBeInstanceOf<UnsupportedCryptoException>()
    }
}
