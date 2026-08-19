package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import java.security.spec.MGF1ParameterSpec
import kotlin.getValue


val SignatureAlgorihmTest by matrixSuite {
    "Minimum key sizes for known digests match expected values" - {
        data class TestSpec(val padding: RSAAlgorithm.Padding, val digest: WellKnownDigest, val expected: Int)
        sequenceOf(
            TestSpec(RSAAlgorithm.Padding.PKCS1, Digest.SHA1, 46),
            TestSpec(RSAAlgorithm.Padding.PKCS1, Digest.SHA256, 62),
            TestSpec(RSAAlgorithm.Padding.PKCS1, Digest.SHA384, 78),
            TestSpec(RSAAlgorithm.Padding.PKCS1, Digest.SHA512, 94),
            TestSpec(RSAAlgorithm.Padding.PSS, Digest.SHA1, 42),
            TestSpec(RSAAlgorithm.Padding.PSS, Digest.SHA256, 66),
            TestSpec(RSAAlgorithm.Padding.PSS, Digest.SHA384, 98),
            TestSpec(RSAAlgorithm.Padding.PSS, Digest.SHA512, 130),
        ).asData(nameFn = { "${it.padding}/${it.digest}" }).test { spec ->
            RSAAlgorithm(spec.padding, spec.digest).minimumKeySize shouldBe spec.expected
        }
    }
    "RSA PSS from digest matches default params" - {
        data class PSSSpec(val digest: WellKnownDigest, val spec: MGF1ParameterSpec, val salt: Int, val trailer: Int)
        sequenceOf(
            PSSSpec(Digest.SHA1, MGF1ParameterSpec.SHA1, 20, 1),
            PSSSpec(Digest.SHA256, MGF1ParameterSpec.SHA256, 32, 1),
            PSSSpec(Digest.SHA384, MGF1ParameterSpec.SHA384, 48, 1),
            PSSSpec(Digest.SHA512, MGF1ParameterSpec.SHA512, 64, 1),
        ).asData(nameFn = { it.digest.name }).test { spec ->
            val params = RSAAlgorithm.Parameters.PssPadded(spec.digest).jcaPSSParams
            params.digestAlgorithm shouldBe spec.digest.jcaName
            params.mgfAlgorithm shouldBe "MGF1"
            params.mgfParameters shouldBe spec.spec
            params.saltLength shouldBe spec.salt
            params.trailerField shouldBe spec.trailer
        }
    }
}