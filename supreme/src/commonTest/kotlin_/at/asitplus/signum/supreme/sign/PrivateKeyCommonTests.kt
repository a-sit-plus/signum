package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.supreme.isSuccess
import at.asitplus.signum.supreme.signature
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import kotlin.random.Random

@OptIn(SecretExposure::class)
class PrivateKeyCommonTests : FreeSpec({
    "RSA" {
        val rsa = """
            -----BEGIN PRIVATE KEY-----
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
            -----END PRIVATE KEY-----
        """.trimIndent()

        val key = CryptoPrivateKey.decodeFromPem(rsa).getOrThrow() as CryptoPrivateKey.WithPublicKey<*>

        val signer: Signer = SignatureAlgorithm.RSAwithSHA256andPSSPadding.signerFor(key).getOrThrow()

        val data = Random.nextBytes(384)
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
        val privateKey = CryptoPrivateKey.decodeFromPem(pkcs8).getOrThrow() as CryptoPrivateKey.EC.WithPublicKey


        val signer: Signer = SignatureAlgorithm.ECDSAwithSHA256.signerFor(privateKey).getOrThrow()

        val data = Random.Default.nextBytes(1024)
        val signature = signer.sign(data)
        signature.isSuccess shouldBe true



        signer.signatureAlgorithm.verifierFor(signer.publicKey).getOrThrow()
            .verify(data, signature.signature).isSuccess shouldBe true
    }

    "Export EC" {
        val signer = Signer.Ephemeral { ec {} }.getOrThrow()
        val privateKey = signer.exportPrivateKey().getOrThrow()
        signer.publicKey shouldBe privateKey.publicKey

        val data = Random.Default.nextBytes(1024)
        val sig = signer.signatureAlgorithm.signerFor(privateKey).getOrThrow().sign(data).signature

        signer.signatureAlgorithm.verifierFor(signer.publicKey).getOrThrow().verify(data, sig).isSuccess shouldBe true
    }

    "Export RSA" {
        val signer = Signer.Ephemeral { rsa {} }.getOrThrow()
        val privateKey = signer.exportPrivateKey().getOrThrow()
        signer.publicKey shouldBe privateKey.publicKey

        val data = Random.Default.nextBytes(1024)
        val sig = signer.signatureAlgorithm.signerFor(privateKey).getOrThrow().sign(data).signature

        signer.signatureAlgorithm.verifierFor(signer.publicKey).getOrThrow().verify(data, sig).isSuccess shouldBe true
    }

    "Regressions" - {
        "#233" {
            @OptIn(ExperimentalStdlibApi::class)
            CryptoPrivateKey.decodeFromDer("3041020100301306072a8648ce3d020106082a8648ce3d03010704273025020101042001811d2b378be969f614283650e8ca3b07eba2289841239513e24fd230e5a538".hexToByteArray())
        }
    }
})