package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.decodeFromPem
import at.asitplus.signum.supreme.isSuccess
import at.asitplus.signum.supreme.signature
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class PrivateKeyCommonTests : FreeSpec({
    "RSA" {
        val rsa = """-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKNwapOQ6rQJHetP
HRlJBIh1OsOsUBiXb3rXXE3xpWAxAha0MH+UPRblOko+5T2JqIb+xKf9Vi3oTM3t
KvffaOPtzKXZauscjq6NGzA3LgeiMy6q19pvkUUOlGYK6+Xfl+B7Xw6+hBMkQuGE
nUS8nkpR5mK4ne7djIyfHFfMu4ptAgMBAAECgYA+s0PPtMq1osG9oi4xoxeAGikf
JB3eMUptP+2DYW7mRibc+ueYKhB9lhcUoKhlQUhL8bUUFVZYakP8xD21thmQqnC4
f63asad0ycteJMLb3r+z26LHuCyOdPg1pyLk3oQ32lVQHBCYathRMcVznxOG16VK
I8BFfstJTaJu0lK/wQJBANYFGusBiZsJQ3utrQMVPpKmloO2++4q1v6ZR4puDQHx
TjLjAIgrkYfwTJBLBRZxec0E7TmuVQ9uJ+wMu/+7zaUCQQDDf2xMnQqYknJoKGq+
oAnyC66UqWC5xAnQS32mlnJ632JXA0pf9pb1SXAYExB1p9Dfqd3VAwQDwBsDDgP6
HD8pAkEA0lscNQZC2TaGtKZk2hXkdcH1SKru/g3vWTkRHxfCAznJUaza1fx0wzdG
GcES1Bdez0tbW4llI5By/skZc2eE3QJAFl6fOskBbGHde3Oce0F+wdZ6XIJhEgCP
iukIcKZoZQzoiMJUoVRrA5gqnmaYDI5uRRl/y57zt6YksR3KcLUIuQJAd242M/WF
6YAZat3q/wEeETeQq1wrooew+8lHl05/Nt0cCpV48RGEhJ83pzBm3mnwHf8lTBJH
x6XroMXsmbnsEw==
-----END PRIVATE KEY-----"""

        val key = CryptoPrivateKey.decodeFromPem(rsa).getOrThrow()

        val signer: Signer = SignatureAlgorithm.RSAwithSHA256andPSSPadding.signerFor(key).getOrThrow()

        val data = "WUMBO".encodeToByteArray()
        val signature = signer.sign(data)
        signature.isSuccess shouldBe true



        signer.signatureAlgorithm.verifierFor(signer.publicKey).getOrThrow()
            .verify(data, signature.signature).isSuccess shouldBe true

    }

    "EC" {
        val pkcs8 = """
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbAdTcsqPZ8LGJRYH
            vqMKfEg4nYoCBgptgZrKzyH+D6ChRANCAARP5mvy+sX6R2vXOmMre59S/V93sNLS
            zxh/z83LcdvgjntLPbRlpulusOaoUHsCataF16M48ef34ufnWLjZsJ0Z
            -----END PRIVATE KEY-----
        """.trimIndent()
        val privateKey = CryptoPrivateKey.decodeFromPem(pkcs8).getOrThrow()


        val signer: Signer = SignatureAlgorithm.ECDSAwithSHA256.signerFor(privateKey).getOrThrow()

        val data = "WUMBO".encodeToByteArray()
        val signature = signer.sign(data)
        signature.isSuccess shouldBe true



        signer.signatureAlgorithm.verifierFor(signer.publicKey).getOrThrow()
            .verify(data, signature.signature).isSuccess shouldBe true
    }
})