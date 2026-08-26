package at.asitplus.signum.supreme.agree

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.KeyAgreementPrivateValue
import at.asitplus.signum.indispensable.decodeFromPem
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
val KeyAgreementTest by matrixSuite {

    "000 Key Agreement Simple Equality Test" {
        val self = KeyAgreementPrivateValue.ECDH.Ephemeral(ECCurve.SECP_256_R_1)


        val pkcs8 = """
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbAdTcsqPZ8LGJRYH
            vqMKfEg4nYoCBgptgZrKzyH+D6ChRANCAARP5mvy+sX6R2vXOmMre59S/V93sNLS
            zxh/z83LcdvgjntLPbRlpulusOaoUHsCataF16M48ef34ufnWLjZsJ0Z
            -----END PRIVATE KEY-----
        """.trimIndent()
        val other =
            CryptoPrivateKey.decodeFromPem(pkcs8) as KeyAgreementPrivateValue.ECDH

        val symmetric1 = self.keyAgreement(other.publicValue)
        val symmetric2 = other.keyAgreement(self.publicValue)

        symmetric1 shouldBe symmetric2

    }

    "Key Agreement Failure Test" - {
        repeat(100) {
            listOf(ECCurve.SECP_384_R_1 to false, ECCurve.SECP_521_R_1 to false, ECCurve.SECP_256_R_1 to true).asData() test { (crv, success) ->
                val base = KeyAgreementPrivateValue.ECDH.Ephemeral(ECCurve.SECP_256_R_1)
                val other = KeyAgreementPrivateValue.ECDH.Ephemeral(crv)

                if (success) {
                    val key1 = shouldNotThrowAny { other.keyAgreement(base.publicValue) }
                    val key2 = shouldNotThrowAny { base.keyAgreement(other.publicValue) }
                    key1 shouldBe key2
                    KeyAgreementPrivateValue.ECDH.Ephemeral(crv)
                        .keyAgreement(base.publicValue) shouldNotBe key1
                    KeyAgreementPrivateValue.ECDH.Ephemeral(crv)
                        .keyAgreement(other.publicValue) shouldNotBe key2
                } else {
                    shouldThrowAny { other.keyAgreement(base.publicValue) }
                    shouldThrowAny { base.keyAgreement(other.publicValue) }
                }
            }
        }

    }
}
