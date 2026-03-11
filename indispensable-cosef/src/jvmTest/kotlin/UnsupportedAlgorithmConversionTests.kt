import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.AlgorithmRegistry
import at.asitplus.signum.indispensable.MessageAuthenticationCode
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.algorithm.toCoseAlgorithm
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.symmetric.AuthCapability
import at.asitplus.signum.indispensable.symmetric.KeyType
import at.asitplus.signum.indispensable.symmetric.NonceTrait
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.types.shouldBeInstanceOf

val UnsupportedAlgorithmConversionTests by testSuite {
    "custom signature algorithm has no COSE mapping" {
        val custom = object : SignatureAlgorithm {
            override fun toString() = "UnsupportedSignatureAlgorithm"
        }
        SignatureAlgorithm.register(custom)

        custom.toCoseAlgorithm().exceptionOrNull().shouldBeInstanceOf<UnsupportedCryptoException>()
    }

    "custom MAC algorithm has no COSE mapping" {
        val custom = object : MessageAuthenticationCode {
            override val outputLength = 128.bit
            override fun toString() = "UnsupportedMacAlgorithm"
        }
        AlgorithmRegistry.registerMessageAuthenticationCode(custom)

        custom.toCoseAlgorithm().exceptionOrNull().shouldBeInstanceOf<UnsupportedCryptoException>()
    }

    "custom symmetric algorithm has no COSE mapping" {
        val custom =
            object : SymmetricEncryptionAlgorithm.Unauthenticated<NonceTrait.Without>,
                SymmetricEncryptionAlgorithm.WithoutNonce<AuthCapability.Unauthenticated, KeyType.Integrated> {
                override val oid = ObjectIdentifier("1.3.6.1.4.1.55555.2")
                override val name = "UnsupportedSymmetricAlgorithm"
                override val keySize = 128.bit
                override fun toString() = name
            }
        AlgorithmRegistry.registerSymmetricEncryptionAlgorithm(custom)

        custom.toCoseAlgorithm().exceptionOrNull().shouldBeInstanceOf<UnsupportedCryptoException>()
    }
}
