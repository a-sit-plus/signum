package at.asitplus.signum.supreme.agree

import at.asitplus.signum.indispensable.PrivateKey
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.agree.KeyAgreementPrivateValue
import at.asitplus.signum.indispensable.agree.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.agree.keyAgreement
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val KeyAgreementTest by matrixSuite {

    "Open agreement values are rejected explicitly by the built-in operation" {
        val ecdhPrivate = KeyAgreementPrivateValue.ECDH.Ephemeral(ECCurve.SECP_256_R_1)
        val ecdhPeer = ecdhPrivate.publicValue
        val unsupportedPeer = object : KeyAgreementPublicValue {
            override val sourceRepresentation = SourceRepresentationStorage()
        }
        val privateValue = object : KeyAgreementPrivateValue {
            override val publicValue: KeyAgreementPublicValue = unsupportedPeer
        }

        shouldThrow<UnsupportedCryptoException> { privateValue.keyAgreement(ecdhPeer) }
        shouldThrow<UnsupportedCryptoException> { privateValue.keyAgreement(unsupportedPeer) }
        shouldThrow<IllegalArgumentException> { ecdhPrivate.keyAgreement(unsupportedPeer) }
    }

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
            PrivateKey.fromAsn1(pkcs8) as KeyAgreementPrivateValue.ECDH

        val symmetric1 = self.keyAgreement(other.publicValue)
        val symmetric2 = other.keyAgreement(self.publicValue)

        symmetric1 shouldBe symmetric2

        val decodedPublicValue = KeyAgreementPublicValue.fromAsn1(self.publicValue.asn1)
        (decodedPublicValue as KeyAgreementPublicValue.ECDH).asPublicKey() shouldBe self.publicValue.asPublicKey()

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
