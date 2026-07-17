@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)
package at.asitplus.signum
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.secKeyAlgorithm
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA256

val Test  by matrixSuite {
    "This dummy test" {
        "is just making sure" shouldNotBe "that iOS tests are indeed running"
    }
}

val IosRsaPssParametersTest by matrixSuite {
    "Apple-compatible parameters map to SecKey" {
        SignatureAlgorithm.RSA(
            SignatureAlgorithm.RSA.Parameters.PssPadded(Digest.SHA256)
        ).secKeyAlgorithm shouldBe kSecKeyAlgorithmRSASignatureMessagePSSSHA256
    }

    "custom MGF digest is rejected" {
        shouldThrow<IllegalArgumentException> {
            SignatureAlgorithm.RSA(
                SignatureAlgorithm.RSA.Parameters.PssPadded(
                    digest = Digest.SHA256,
                    mgfAlgorithm = SignatureAlgorithm.RSA.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1(
                        Digest.SHA1
                    )
                )
            ).secKeyAlgorithm
        }
    }
}
