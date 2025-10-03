package at.asitplus.signum.supreme.agree

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.KeyAgreementPrivateValue
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

val KeyAgreementTest by testSuite(testConfig = TestConfig.testScope(isEnabled = true, timeout = 20.minutes)) {

    "000 Key Agreement Simple Equality Test" {
        val self = KeyAgreementPrivateValue.ECDH.Ephemeral(ECCurve.SECP_256_R_1).getOrThrow()


        val pkcs8 = """
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbAdTcsqPZ8LGJRYH
            vqMKfEg4nYoCBgptgZrKzyH+D6ChRANCAARP5mvy+sX6R2vXOmMre59S/V93sNLS
            zxh/z83LcdvgjntLPbRlpulusOaoUHsCataF16M48ef34ufnWLjZsJ0Z
            -----END PRIVATE KEY-----
        """.trimIndent()
        val other =
            CryptoPrivateKey.decodeFromPem(pkcs8).getOrThrow() as KeyAgreementPrivateValue.ECDH

        val symmetric1 = self.keyAgreement(other.publicValue).getOrThrow()
        val symmetric2 = other.keyAgreement(self.publicValue).getOrThrow()

        symmetric1 shouldBe symmetric2

    }

    "Key Agreement Failure Test" - {
        repeat(100) {
            val base = KeyAgreementPrivateValue.ECDH.Ephemeral(ECCurve.SECP_256_R_1).getOrThrow()

            withData(
                ECCurve.SECP_384_R_1 to false,
                ECCurve.SECP_521_R_1 to false,
                ECCurve.SECP_256_R_1 to true
            ) { (crv, success) ->
                val other = KeyAgreementPrivateValue.ECDH.Ephemeral(crv).getOrThrow()
                other.keyAgreement(base.publicValue).isSuccess shouldBe success
                base.keyAgreement(other.publicValue).isSuccess shouldBe success

                if (success) {
                    val agreed = other.keyAgreement(base.publicValue).getOrThrow()
                    agreed shouldBe base.keyAgreement(other.publicValue).getOrThrow()
                    KeyAgreementPrivateValue.ECDH.Ephemeral(crv).getOrThrow()
                        .keyAgreement(base.publicValue) shouldNotBe agreed
                    KeyAgreementPrivateValue.ECDH.Ephemeral(crv).getOrThrow()
                        .keyAgreement(other.publicValue) shouldNotBe agreed
                }
            }
        }

    }
}