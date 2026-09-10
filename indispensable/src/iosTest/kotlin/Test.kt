@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)
package at.asitplus.signum
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.secKeyAlgorithm
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA256

val IosRsaPssParametersTest by matrixSuite {
    "Apple-compatible parameters map to SecKey" {
        RsaAlgorithm(
            RsaAlgorithm.Parameters.PssPadded(Digest.SHA256)
        ).secKeyAlgorithm shouldBe kSecKeyAlgorithmRSASignatureMessagePSSSHA256
    }

    "custom MGF digest is rejected" {
        shouldThrow<UnsupportedCryptoException> {
            RsaAlgorithm(
                RsaAlgorithm.Parameters.PssPadded(
                    digest = Digest.SHA256,
                    mgfAlgorithm = RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1(
                        Digest.SHA1
                    )
                )
            ).secKeyAlgorithm
        }
    }
}
