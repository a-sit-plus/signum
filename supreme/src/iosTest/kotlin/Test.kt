package wumb

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.decodeFromPem
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.toSecKey
import at.asitplus.signum.supreme.sign.PrivateKeySigner
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify
import at.asitplus.signum.supreme.signature
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.cinterop.ExperimentalForeignApi

@OptIn(ExperimentalForeignApi::class)
class ProviderTest : FreeSpec({

    "This dummy test" {
        "is just making sure" shouldNotBe "that iOS tests are indeed running"
    }

    "RSA" {
        val rsa="""-----BEGIN PRIVATE KEY-----
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

       val key= CryptoPrivateKey.decodeFromPem(rsa)
        val secKey = key.toSecKey()
        println(secKey)

        val signer = PrivateKeySigner(secKey.getOrThrow(), SignatureAlgorithm.RSAwithSHA256andPSSPadding, key.publicKey!!)

        val data = "WUMBO".encodeToByteArray()
        val signature = signer.sign(data)


       println( SignatureAlgorithm.RSAwithSHA256andPSSPadding.verifierFor(key.publicKey!!).getOrThrow().verify(data,signature.signature))

    }

    "EC" {
        val pkcs8="""
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbAdTcsqPZ8LGJRYH
            vqMKfEg4nYoCBgptgZrKzyH+D6ChRANCAARP5mvy+sX6R2vXOmMre59S/V93sNLS
            zxh/z83LcdvgjntLPbRlpulusOaoUHsCataF16M48ef34ufnWLjZsJ0Z
            -----END PRIVATE KEY-----
        """.trimIndent()
        val privateKey= CryptoPrivateKey.decodeFromPem(pkcs8)

        val secKey = privateKey.toSecKey()
        println(secKey)

        val signer = PrivateKeySigner(secKey.getOrThrow(), SignatureAlgorithm.ECDSAwithSHA256, privateKey.publicKey!!)

        val data = "WUMBO".encodeToByteArray()
        val signature = signer.sign(data)


        println( SignatureAlgorithm.ECDSAwithSHA256.verifierFor(privateKey.publicKey!!).getOrThrow().verify(data,signature.signature))
    }
})