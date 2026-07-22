@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)
package at.asitplus.signum
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.secKeyAlgorithm
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA256

val IosRsaPssParametersTest by matrixSuite {
    "Apple-compatible parameters map to SecKey" {
        SignatureAlgorithm.RSA(
            SignatureAlgorithm.RSA.Parameters.PssPadded(Digest.SHA256)
        ).secKeyAlgorithm shouldBe kSecKeyAlgorithmRSASignatureMessagePSSSHA256
    }

    "custom MGF digest is rejected" {
        shouldThrow<UnsupportedCryptoException> {
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
