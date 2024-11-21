import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.asn1.decodeFromPem
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class PemTest: FreeSpec( {
    "Manual" {
        val sec1= """
            -----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIGwHU3LKj2fCxiUWB76jCnxIOJ2KAgYKbYGays8h/g+goAoGCCqGSM49
            AwEHoUQDQgAET+Zr8vrF+kdr1zpjK3ufUv1fd7DS0s8Yf8/Ny3Hb4I57Sz20Zabp
            brDmqFB7AmrWhdejOPHn9+Ln51i42bCdGQ==
            -----END EC PRIVATE KEY-----
        """.trimIndent()

        CryptoPrivateKey.EC.decodeFromPem(sec1).pemEncodeSec1() shouldBe sec1

        val pkcs8="""
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbAdTcsqPZ8LGJRYH
            vqMKfEg4nYoCBgptgZrKzyH+D6ChRANCAARP5mvy+sX6R2vXOmMre59S/V93sNLS
            zxh/z83LcdvgjntLPbRlpulusOaoUHsCataF16M48ef34ufnWLjZsJ0Z
            -----END PRIVATE KEY-----
        """.trimIndent()
        CryptoPrivateKey.decodeFromPem(pkcs8).encodeToPEM() shouldBe pkcs8
    }
})