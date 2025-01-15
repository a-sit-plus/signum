package at.asitplus.signum.supreme.agreement

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.supreme.SecretExposure
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.signerFor
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

@OptIn(SecretExposure::class)
class KeyAgreementTest : FreeSpec({

    "000 Key Agreement Simple Equality Test" {
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
        val other =
            CryptoPrivateKey.decodeFromPem(pkcs8).getOrThrow() as CryptoPrivateKey.EC.WithPublicKey

        self as Signer.ECDSA
        val symmetric1 = self.keyAgreement(other.publicKey).getOrThrow()

        val signerExt = SignatureAlgorithm.ECDSAwithSHA256.signerFor(other).getOrThrow()
        signerExt as Signer.ECDSA
        val symmetrc2 = signerExt.keyAgreement(self.publicKey).getOrThrow()

        symmetric1 shouldBe symmetrc2

    }

    "Key Agreement Failure Test" - {
        repeat(100) {
            val base = Signer.Ephemeral {
                ec {
                    curve = ECCurve.SECP_256_R_1
                }
            }.getOrThrow() as Signer.ECDSA

            withData(
                ECCurve.SECP_384_R_1 to false,
                ECCurve.SECP_521_R_1 to false,
                ECCurve.SECP_256_R_1 to true
            ) { (crv, success) ->
                val other = Signer.Ephemeral { ec { curve = crv } }.getOrThrow() as Signer.ECDSA
                other.keyAgreement(base.publicKey).isSuccess shouldBe success
                base.keyAgreement(other.publicKey).isSuccess shouldBe success
                (base.exportPrivateKey().getOrThrow() as CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC>).keyAgreement(other.publicKey).isSuccess shouldBe success
                (other.exportPrivateKey().getOrThrow() as CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC>).keyAgreement(base.publicKey).isSuccess shouldBe success

                if(success){
                    val agreed = other.keyAgreement(base.publicKey).getOrThrow()
                    agreed shouldBe base.keyAgreement(other.publicKey).getOrThrow()
                    agreed shouldBe (base.exportPrivateKey().getOrThrow() as CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC>).keyAgreement(other.publicKey).getOrThrow()
                    agreed shouldBe (other.exportPrivateKey().getOrThrow() as CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC>).keyAgreement(base.publicKey).getOrThrow()

                    (Signer.Ephemeral { ec { curve = crv } }.getOrThrow() as Signer.ECDSA).keyAgreement(base.publicKey) shouldNotBe agreed
                    (Signer.Ephemeral { ec { curve = crv } }.getOrThrow() as Signer.ECDSA).keyAgreement(other.publicKey) shouldNotBe agreed
                }
            }
        }

    }

})