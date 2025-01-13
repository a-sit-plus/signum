package at.asitplus.signum.supreme.agreement

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.signerFor
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class KeyAgreementTest : FreeSpec({

    "000 Key Agreement Simple Equality Test" - {
        val self = Signer.Ephemeral {
            ec {
                curve = ECCurve.SECP_256_R_1
            }
        }.getOrThrow()


        val pkcs8 = """
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbAdTcsqPZ8LGJRYH
            vqMKfEg4nYoCBgptgZrKzyH+D6ChRANCAARP5mvy+sX6R2vXOmMre59S/V93sNLS
            zxh/z83LcdvgjntLPbRlpulusOaoUHsCataF16M48ef34ufnWLjZsJ0Z
            -----END PRIVATE KEY-----
        """.trimIndent()
        val other = CryptoPrivateKey.decodeFromPem(pkcs8).getOrThrow() as CryptoPrivateKey.EC.WithPublicKey

        self as Signer.ECDSA
        val symmetric1 = self.keyAgreement(other.publicKey).getOrThrow()

        val signerExt = SignatureAlgorithm.ECDSAwithSHA256.signerFor(other).getOrThrow()
        signerExt as Signer.ECDSA
        val symmetrc2 = signerExt.keyAgreement(self.publicKey).getOrThrow()

        symmetric1 shouldBe symmetrc2


    }

})