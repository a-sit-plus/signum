package at.asitplus.signum.supreme

import at.asitplus.signum.dsl.JCAProviderRef
import at.asitplus.signum.dsl.Of
import at.asitplus.signum.dsl.jvm
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import org.bouncycastle.jce.provider.BouncyCastleProvider
import kotlin.random.Random

val AndroidRSAPSSQuirksTest by matrixSuite {
    "Specific provider (not AndroidKeyStore)" {
        val signer = Signer.Ephemeral {
            rsa { padding = RSAAlgorithm.Padding.PKCS1 }
            jvm { provider = JCAProviderRef.Of(BouncyCastleProvider()) }
        }
        shouldNotThrowAny { val _ = signer.sign(Random.nextBytes(16)).signature }
    }
}
