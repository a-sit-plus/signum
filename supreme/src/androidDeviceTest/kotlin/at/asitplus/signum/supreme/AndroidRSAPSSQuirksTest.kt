package at.asitplus.signum.supreme

import at.asitplus.signum.dsl.jvm
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import kotlin.random.Random

val AndroidRSAPSSQuirksTest by matrixSuite {
    "Specific provider (not AndroidKeyStore)" {
        val hasBC = Security.getProviders().any { it.name == BouncyCastleProvider.PROVIDER_NAME }
        if (!hasBC) Security.addProvider(BouncyCastleProvider())
        val signer = Signer.Ephemeral {
            rsa { padding = RSAAlgorithm.Padding.PKCS1 }
            jvm { provider = BouncyCastleProvider.PROVIDER_NAME }
        }
        shouldNotThrowAny { signer.sign(Random.nextBytes(16)).signature }
        if (!hasBC) Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
    }
}
