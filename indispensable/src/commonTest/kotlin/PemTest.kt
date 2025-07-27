package at.asitplus.signum

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.X509Certificate

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random

@OptIn(ExperimentalStdlibApi::class)
class PemTest : FreeSpec({

   
    "Cert"  {
        val pemEC= """
            -----BEGIN CERTIFICATE-----
            MIIBGzCBwqADAgECAhRNToTfnnyTUnaag1qQmgGR+b3WhjAKBggqhkjOPQQDAjAO
            MQwwCgYDVQQDDANmb28wHhcNMjQwOTE2MDczMDUzWhcNMjUwOTE2MDczMDUzWjAO
            MQwwCgYDVQQDDANmb28wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASnuk0LMIGG
            YF2uoFYQhu/K6j4B9fJSBAWtxIUIUbzPUhu0OdDHJ9KkRFxwdk9NAW1PfJp/K7oK
            4J+lV0nW7Ms5MAoGCCqGSM49BAMCA0gAMEUCIQDTFPR4YuQWSFB42aC0EQLIzPVS
            dezRKC3czsyJJ5ofHAIgFFejWT9Fzphb+Mfx51bDRlJo9sd27a3RS7bj5euMliI=
            -----END CERTIFICATE-----
        """.trimIndent()

        val cert= X509Certificate.decodeFromPem(pemEC).getOrThrow()
        cert.encodeToPEM().getOrThrow() shouldBe pemEC
        val pemRSA= """
            -----BEGIN CERTIFICATE-----
            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
            -----END CERTIFICATE-----
        """.trimIndent()

        val certRSA= X509Certificate.decodeFromPem(pemRSA).getOrThrow()
        certRSA.encodeToPEM().getOrThrow() shouldBe pemRSA
    }

    "EC Public Key" {
        val pem = """
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp7pNCzCBhmBdrqBWEIbvyuo+AfXy
            UgQFrcSFCFG8z1IbtDnQxyfSpERccHZPTQFtT3yafyu6CuCfpVdJ1uzLOQ==
            -----END PUBLIC KEY-----
        """.trimIndent()

        val key = CryptoPublicKey.decodeFromPem(pem).getOrThrow().shouldBeInstanceOf<CryptoPublicKey.EC>()
    }
    "CSR" {
        val pem = """
        -----BEGIN CERTIFICATE REQUEST-----
        MIHIMHACAQAwDjEMMAoGA1UEAwwDZm9vMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp7pNCzCB
        hmBdrqBWEIbvyuo+AfXyUgQFrcSFCFG8z1IbtDnQxyfSpERccHZPTQFtT3yafyu6CuCfpVdJ1uzL
        OaAAMAoGCCqGSM49BAMCA0gAMEUCIHoyk9gs6Dr/KInrGScLAPz95B0oM69wTSCEJJS8vd6KAiEA
        tu/uftQ1s6YROFuJp5Tn5OddM1B73uZa6HnFhYv7VF0=
        -----END CERTIFICATE REQUEST-----
        """.trimIndent()

        val csr  = Pkcs10CertificationRequest.decodeFromPem(pem).getOrThrow().shouldBeInstanceOf<Pkcs10CertificationRequest>()
        csr.tbsCsr.publicKey.shouldBeInstanceOf<CryptoPublicKey.EC>()
    }

    "RSA Public Key" {
        val pem = """
           -----BEGIN PUBLIC KEY-----
            MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAregkc/QUN/ObnitXKByH
            vty33ziQjG485legePd1wqL+9Wpu9gBPKNveaIZsRJO2sWP9FBJrvx/S6jGbIX7R
            Mzy6SPXded+zuP8S8SGaS8GKhnFpSmZmbI9+PHC/rSkiBvPkwOaAruJLj7eZfpQD
            n9NHl3yZSCNT6DiuTwpvgy7RSVeMgHS22i/QOI17A3AhG3XyMDz6j67d2mOr6xZP
            wo4RS37PC+j/tXcu9LJ7SuBMEiUMcI0DKaDhUyTsE9nuGb8Qs0qMP4mjYVHerIcH
            lPRjcewu4m9bmIHhiVw0eWx27zuQYnnm26SaLybF0BDhDt7ZEI4W+7f3qPfH5QIH
            mI82CJXn4jeWDTZ1nvsOcrEdm7wD+UkF2IHdBbQq1kHprAF2lQoP2N/VvRIfNS8o
            F2zSmMGoCWR3bkc3us6sWV5onX9y1onFBkEpPlk+3Sb1JMkRp1qjTEAfRqGZtac6
            UW6GO559cqcSBXhZ7T5ReBULA4+N0C8Fsj57ShxLcwUS/Mbq4FATfEOTdLPKdOeO
            HwEI0DDUW3E2tAe6wTAwXEi3gjuYpn1giqKjKYLMur2DBBuigwNBodYF8RvCtvCo
            fIY7RqhIKojcdpp2vx9qpT0Zj+s482TeyCsNCij/99viFULUItAnXeF5/hjncIit
            TubZizrG3SdRbv+8ZPUzQ08CAwEAAQ==
            -----END PUBLIC KEY-----
        """.trimIndent()

        val rsa = CryptoPublicKey.decodeFromPem(pem).getOrThrow().shouldBeInstanceOf<CryptoPublicKey.RSA>()

        val pkcs1= """
            -----BEGIN RSA PUBLIC KEY-----
            MIIBigKCAYEAq3DnhgYgLVJknvDA3clATozPtjI7yauqD4/ZuqgZn4KzzzkQ4BzJ
            ar4jRygpzbghlFn0Luk1mdVKzPUgYj0VkbRlHyYfcahbgOHixOOnXkKXrtZW7yWG
            jXPqy/ZJ/+...
            -----END RSA PUBLIC KEY-----
        """.trimIndent()

         CryptoPublicKey.decodeFromPem(pem).getOrThrow().shouldBeInstanceOf<CryptoPublicKey.RSA>()
    }


    val rnd = Random.nextBytes(35).toHexString() + "\n                  "
    "SEC1" {
        val sec1 = """
            -----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIGwHU3LKj2fCxiUWB76jCnxIOJ2KAgYKbYGays8h/g+goAoGCCqGSM49
            AwEHoUQDQgAET+Zr8vrF+kdr1zpjK3ufUv1fd7DS0s8Yf8/Ny3Hb4I57Sz20Zabp
            brDmqFB7AmrWhdejOPHn9+Ln51i42bCdGQ==
            -----END EC PRIVATE KEY-----
        """.trimIndent()

        CryptoPrivateKey.decodeFromPem(rnd + sec1).getOrThrow().let {
            it.shouldBeInstanceOf<CryptoPrivateKey.EC>()
            CryptoPrivateKey.EC.decodeFromPem(sec1).getOrThrow() shouldBe it
            CryptoPrivateKey.RSA.decodeFromPem(sec1).isSuccess shouldBe false

            it.asSEC1.encodeToPEM().getOrThrow().lines() shouldBe sec1.lines()
        }
    }

    "PKCS#8" {
        val pkcs8 = """
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbAdTcsqPZ8LGJRYH
            vqMKfEg4nYoCBgptgZrKzyH+D6ChRANCAARP5mvy+sX6R2vXOmMre59S/V93sNLS
            zxh/z83LcdvgjntLPbRlpulusOaoUHsCataF16M48ef34ufnWLjZsJ0Z
            -----END PRIVATE KEY-----
        """.trimIndent()

        CryptoPrivateKey.decodeFromPem(rnd + pkcs8).getOrThrow().let {
            CryptoPrivateKey.EC.decodeFromPem(pkcs8).getOrThrow() shouldBe it
            CryptoPrivateKey.RSA.decodeFromPem(pkcs8).isSuccess shouldBe false
            it.encodeToPEM().getOrThrow().lines() shouldBe pkcs8.lines()
        }
    }



    "from iOS" {
        val rsa = listOf(
            "308206e40201000282018100984a14a911fd17685b69f6d41722a7d8250de916cf4acaf097ede373626a6c67284ef953692f43bd48b075890f70422822b9254f9a1ac7038b97e3da6ee0efa080fe16cb7355c0b43f4df77634a8c943745b2313e46ff28c4377576fb934bb2a099a81dea9c69335a52f2b5e7c357f608cd9a7d6d71f7e3932f2df46ff704c279418807fdd179a75e930f61b9e4c27b003d63f7f562d71db128d8735f75cdd907706b5630b7e69a31357d816b73d2807c5bf90cc10a6d7d04088d4d80116be7119fdf8676e50557da72afe20543dfe6acc35b12614ca45780c3e5670c63c3a18fe937fbb0bf7284eac03d4b80d600ee1bdb7e536d0d590baffaed3bcd9f873a5591d6faeaeae4d0058114946df844bc3125a51310de06149a97fdb929a8938255ac4a5bf070fcc932b37ef94b639cafff7dc4e3a901c7bfa69b1cd8bd8dfb86a1967b6b9cdc2307020feef9ce6534d1b22f8f5a00761d6f7308b8d3de0e043be14aa57f1afa112daf0b8b8c48473e21db1ec48dd848bed0aa243e7f833cfbbd9020301000102820180399450e977e6b491fd763c2006bb50b0d599c3d69efbcd6d5854569a4acca83dfcac97726523bcbdf59cda63bf1597bdeb1b0bb36435d9a74a815c623b680ad229d36834f65fa6e3bfc7afd7dea32eadb571bbfa8a7595445941e72a53e14f1eded0af67cbd34bd78da41f06b379dab65baaf3ddb42ab123d952a0ff0c179e839c680335d517568c5c65e9b7998b7bb9fe49646ab5dfaadbc4d1041d7070894954e7916f686a1c70cf2078906629d657d1f9d33a84d54065f9f0826145501f22b8f5f005fc30f9de4bcb85db21305c2b3445c820122e86ceaf76e033791d855e07f49d9685a0e6e3d148cdad95737e476021293e406e0f3b055ddd5f7222f5b85e18082cf17adbc22b50d56f913fb12c368f7ad0ef865227009781151b6539473cbaa38d5de790f3fcfd23ff7639d8a5ecd313dcc41f0531c4d52e69932e455cbb8840929f17fbbf92af0e4461a43d18db317703896dd1a2ce5c886d63bc4070a2735bf13b863f0159e7ce2200ccf01f20a66068557ebe42457e477b3eb3be3d0281c100c9393384e03e878b1bd4abcf42914ebd050b467a69522ad8794ce5f4686ec2d44ba0ca750f55d9e6c86e6d42594de45a0e8df58bb5ff9787cbdbafc1a80026ce82cc9676b29f04efcd1f059d402e138b25040313fd7f09cf3706e7cf9f9182eca36d25a03aff6efe5826de3b7e2eff8e46b841bb37af98c9e6cff12ff4ae317ebb172f531dfd98948e39f8b3423345f39259791bf18f2f31a2541a86a6f4125b61b1b84090c752e522936c27688f9f7c1838896364d09b603a69d4c5d4cdec370281c100c1bec6ee6f0b83181a2626716fc70ef57667e4f181a44a8c5591b91c879d11a76ea417662017da58b886cbc88740bb72eca3d78fa5c4b15054a3644fab51490df79177db43b5a254438be770e57692ae393bf77880c84e9c5628ce1ba38d0261a8beb27c47d57d20a3927d0be05374cc308407b48ff0124828cdce1d543d0285fcf912b86bd2a7e037cba8e2cd7ee495bedcda334f72858c420cefd6d9497e4b0a9f4b897ebb0f7178e12f3675225f7f0e071716f7013bd09279258f79a4306f0281c100a56b74c2e366041f83bd8d9050f50b79b04fd89c81409f205e77ad0303672a9b43a0e74edc50835589a7de0211504b4d0d71fe4de04c41d1ccf0c8c7b6c8891e73c0a460e7ee7a2c78bfebe99dfd42ebbc7e53d977279c74d093c8b59244191158383e1a3ee605e4e9aaea3e963924b55dc5d3a388dfbe071ccc0d46932b305d328898cb0778969a696196e626a1e7fb98701d73af5d3a3adf6bac72cd8510223769d6429dc27e8f07a191e3c3bd6e2aa1eeb8631159bca19ae3ad9b049a54790281c10094dffacec6a76af1bf4e27662d45217a7ea4b0e8defc9688254c979893a09f2b303a88fc6196d2a23010ec504795f734052095087d9199caa76ef22ac1f2f116f9705f502e4448db4518211cc0460fca2e92a4c384f9e665fd52d7a5a754384b40b660425d946fd4ffbc15b86584db8ff78bccbbf38abf1191c12b2ba04a4d411635722c223639e772185dcb01ab0b0d021f84cfbeb1ba6b1f69ff75f17ba6bf150778accba403e6e6c2ea5b8740856f05216f9da6e9dcc39579dfe1d2cfd6a30281c06c970f100b9ac4f229ad5301728cbd2d4d10fabf961d427add4852e2553f1849ad4889c7fb3b22c2a47d28f95d56ed9635de37a74f148a8dd46da4eeebbc176470972d8dfdfe0fdb65100107cd7c7f7933de512e531118947ed8602d3582753939269c766010577995f5398dd0ae572a2721b8a606a71035a2441cdb1a0a289ec45dd2566d9985f17e1d6f468e5b22a7e399eac5f233500864a141634ee5c34ac16bf6ceb153e2cc6533ee77096c7693a1c2f3bb6352d2562d070ff55d3070b1"
        )
        val ec = listOf(
            "044a58f643eaaf0a2b92e3dfae095838895833449bc2b35b77780e64c134b788c604d9e617ad2b1b1a54e196990f641a069b02d9ae418662194605b204ac134a5ce854127f57a280a012f31930b0acfc41e2bf6afb95c403126da04510ec1f6470452d54594d86e80a88163b80d681f09defd1999c8b4d483f8ef7f7f16f7060e549a76cdae2e241afb9d873f0ede30ab8",
            "04810efff4ab927d512e59fc188af66ce358a8507193e07234109b7a30897efae4baea616cd39a0e838ef691941ac640ef2383069246e9b4cb1795ab8d49b7a0c75ccdd0f2aa1dabeb708cd4cee9f6b26a689fe58ecba48619c80de73996d7a314",
            "04de2217560986e17cb2dda07fedb59055ba986f20162b9f59a3073c8188a9c44618e6c032e5ea41296550a5b5d88975bbb622a83b4658b4659e2e072aa60c593846122445185002b83011c28a2dc85bbcf407a3938dfcb8c9140632cd276df422965910dc5db2e4c7e17fe5fe7bd488014919bdb6a5f7ce497d89d0eed815ebff8993db5052392c0e57cd11b1766a478f",
            "0401c40e2f75a36f7b755b25676c0cdc1d57135e608294b6e4113a6657175f2249e1b5ffca85a788e2ea4d80e7c0f3d92249c52cdb2a42b75c3c127e218926ee64c3ac01616ca696c9206f023ccb3f6cfdb1211c43acaffee4ff9de2480f5c6010ef1fe2eda0a99d3a7f75089085cc57d18651c6bd7e9607336dbf983a9131b4f27c11d1e300eae3316d84dfa529157b57517dfd70de9f11568f22b3967689bff5dd5fe6b2f155d117939bbe55257711977170d762c4334be1968e61c3f02b8f57f34193e5611f",
            "0401e8a1af9610024a8b28af1e619022735c1d42c58780f69b0a5abbe25643e1257e09d3550a2b3c12440ada7574cfa107002eb6f0b87fe8c1ee1f2d7af526a282321900cc9af4b002828883dfb0eabac34f2dd021bf26781e11d547a9bad0c185c7f9d2ab2a62622b5e1202ba68838b7ef1511cb378db70db8e5a27efa23071b92b1efbf900b5875b2d1458c7f03877b5e2dc8adb8111763e4534a4270f3c34ecbd8a779522f94f72358b61742ac0f68175a17e37369b1a80bc89c96862f179c4ea4b5998c20f",
            "049d22ada3fed52d17e890066b707ba9476e4088b2d89e09109ee71a7590e629677f7bf1958e20533a41eaa4c26d371345b68e39b59ae1a36536c0ffa28ad976da0ba7b225d48c46e30e4fc6dbe05b590179f2c6bae0b9714f17c6b1996552dd6a"
        )

        rsa.forEach { string ->
            CryptoPrivateKey.fromIosEncoded(string.hexToByteArray()).getOrThrow()
                .shouldBeInstanceOf<CryptoPrivateKey.RSA>()
        }

        ec.forEach { string ->
            CryptoPrivateKey.fromIosEncoded(string.hexToByteArray()).getOrThrow()
                .shouldBeInstanceOf<CryptoPrivateKey.EC>()

        }
    }

    "PCKS#8 multi-prime RSA" {
        val rsa = listOf(
            """
            -----BEGIN PRIVATE KEY-----
            MIIE8wIBADANBgkqhkiG9w0BAQEFAASCBN0wggTZAgEBAoIBAQDXeS43Ld7bA9mY
            u0yGL3gEmzs8ep7l5kya1G71hlku8n49zU77r4KxC2hbUaTF5HNI6zpfHKw9x4zd
            ogkzmvfy6sG8AeW2z/7UF8zEbLlP5QCkmBC+UccDHfL1IKX5uLjk7G+CpPQrqx8d
            UhkESLbVRrWtQHBRZ6NAq9Ou9bV8DaR213etqS8oNW9fDdRFe3xZwds4fuCK+EUF
            VuFaf0cmRRDPPKIHd9/V+8JZji84y0tES9nzO9vi6D0+iVvkr0yIdv4Rd7BEq110
            gSNL2f+5/7Wrb37arymH/8G1G2lt+iS9avUIMWdWiqSHheIdl92ABeYwVyNGV+m+
            qh77lK8JAgMBAAECggEBAJ7pwonzjJ6eckbQLBnyvGM5UTDDhpkrhmfSMJtnoDKd
            qTlPR+cbhBmqviZLSmigmd23jm9DKEzP9TYoIP0sV52SQZu1EoQHVnt5qg1b2jfw
            Ps8lT4OZwqIzhNq9fpBaeJ+PC9lZ1X4myhL8Lrd8M1ZhlNpc3DGFSqU+yanFRIny
            oNeJNTMORSWC+F4nd6SvRA0ti+LPWML7OD5GQcHceh45l6rUtgXBT73jOYnEVuE1
            vzypoTJGoezqHM3FAkSmY3vM8wt5BIW2WGrBawjnuBapLxbEK44xIZrjdKn50v/F
            9rEkm0oVdGJzgVhImEt3l5tVAz5M0FIqLguIn8SJGQECVgfKpTv9NahXOFwP2qVA
            QZFJ/5CMM+qhbfzmdURwn2PSFF9Htbge8KcDH9vNRcRRbiGO2oySk6eyZNpdxX0M
            iGJ5CXZGOb3x74T4y60zWwp6I+wABn3hAlYHO3O6bJdcRp0K/CXXLgGPMiUu/7Eb
            9KP6nU9XatSNV1QiYQOawFxRs0iE/9UBZGt1EDXPXkht/iLZ99GDfkeztWSQyhNK
            FG2lBEgivfw+i4UreKXXkwJWBNCSvrk/2SDcsPcTE57bZZ6mkHoy8sCCqQ74VCyM
            MjD1adN0Vay45Vum6jq07BWtyoruPoOtPqmcbNwZV6bQ+Jj24eGPePLyIedkZUkg
            7x5+6C0z1cECVgS+dcpKovqvgyIKhhPhJLq2jPeIV7fbwJiLCdlwxR41s4Wdl4yy
            M5yP+rjrS+DO60HtsS5mTSKBeoD58x/K/OOfz+i99Os5/TYqWdsYPlcUk/UQ/dAr
            AlVsrO5k6ROZFE1KA03WsZNQX7ATgtYWdpa7ddo1ydpIw/cZtYOiCqh0F5F0IpXc
            zeF0pvw98xX+LmoOnFNCNbHb1oltrz78UXRpPOPD2x8+9tnR4v3TMIIBDDCCAQgC
            VgPS5KcnT0V5vgxhyiAbGj1UYJPEnG+uUy3pRAgIVJ64ZRKoqYDZAonuNL3yf9T/
            H+ct8REqH9y+doDaFgxabXQg132SrL1TBPGgOmjz60JZnyqaZgjTAlYC/0XcQzKe
            aVtuxyOwYK4DjmSYzo4z97cZEHMTvLvfIPeQVYVvCio0RPMwQ6ixIjw2b0s6QgNx
            ehTW0Jphmmuaj7d4pQQi7bS9U/MUmsQ3YJoiwZziowJWA1Y0RFKFj3VEcCzYZ9mQ
            KZKh3KL8TcNxRSKE884UF+IcYVGGrno6l1+T4069hGA2Rnjfd2z1ueTNvYzFt+SC
            +diIdtTI64K96bzYBltP+ABmUmX5D8Q=
            -----END PRIVATE KEY-----
        """.trimIndent(),
            """
            -----BEGIN PRIVATE KEY-----
            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
            -----END PRIVATE KEY-----
            """.trimIndent(),
            """
            -----BEGIN PRIVATE KEY-----
            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
            -----END PRIVATE KEY-----
            """.trimIndent(),
            """
                -----BEGIN PRIVATE KEY-----
                MIIJ3gIBADANBgkqhkiG9w0BAQEFAASCCcgwggnEAgEBAoICAQCekxy08g5rAGbK
                YCvAd3QnGOMXW09Vyh8IvSybzNI/chNwXQCyYl3k9mEoSFyroNXwyO0sQypOJ0EB
                j/st8GMedFvfVS2IUKVe/J2bMA7s4RGQ5mOlvl5HVsF0Vqf8mna/WwKI7QtuhcQy
                CqtSW6Bf4trYecq1AXY48fFsPgOd2kIob4Sdn9+fiaa+uh3OqBl80rllQMoKGJ6W
                Dfgg8bottuQrLH1LozRX6CBoH2xU1/BckcAD9/+dg6h70fcdYCAc1+Jhhs9cm4yd
                FyFHodm7THxtohm0DhZS/Hos8CQwL+U5qfYaUFeGUldusNZeLLW3h9Zvt47gxYjC
                DrXtvOfQMgBjyW9rSGb5NQEDwGuncyx0Kn/D74+iMKuzajfHBZuEY+N6ssyBHELX
                UXjKawfsc484IZCyi5Dr0INCcFxIay5shrottzZAuhmB6H166W28doqNnc0iBHNC
                whKIDH/dDkjCrPkF5TrqL6JGkdqCeaGjqIORIWO4p0wN5gHaR2YmpQza7d224maF
                kZ6ADSrN/3nvROL7nkCYsx3+UwVDNT/BZiibPeAFEVvTxJ+H6yRN5tarm3bLtxo+
                JTyueWTMme8gAvK2nXOw81eTX1P63K2P4LOExQ3KojY2T0I5Os6jWZmI25siWf9i
                ly7tY0QR1nEnaRC/3S3z6aiE1skgSwIDAQABAoICAGX2ehLvQc4TqASg6gELzigF
                nJ+8GrszB9l6qmBTxyz8kPtDEduh3HYI5lgcj1ncRTRaPgaj+WPfYbE7f2r+kv1W
                HGzyPCDWmj8Fd+H9eNtfrQfa3GAKlFySsDm6LrICMDDCuFKK+TrL0GfM7HQ8bla5
                a7aeOXVBx16+U1oiVfj8PcH7fa21ui76c4fJLcbvgHtf5Ks+SWITqeNlh+bEwsdm
                k3VhJP3oyr/kp63x+Mh4F4WzLuRUCR0TP73iahiHT9U4eHAxHDCLetjZFtsWgXYJ
                zk/aAzfF/4V7TkwrjZU7c9DTC55+orCl1rKdYn/b2zaYbnBmTDexhm1cNLlKKUV2
                if/ndLoaU/dhK1dOpa+lixT7XgtXNcZ26bfVv9q8HaJfQtGFMINB0X8FbeL3YdpH
                Rjdc+ClQTPDlFvGq/tgx+ZKZkVXpmPNpprBwT2b/r7i9oj5tXodg3E2Z6AJixg7Q
                Jd/f1poeoE9bOdIV+P6IIuxp9nm79RILV71gT8bmcBKZ+pJiuSLRnQ3gkH/swHS7
                Bj6e7I5gUMHRqLkbw4k+yyTHxZ5DvFutUnrjc3s7KPNm46ECl5ksT+Iioi2S8xVO
                /qieRwF83EW1ic15Drin89PalNqnNogP4K7u9p7q+xK3BOH5OfCb8DFZBl8J+SMK
                PJSz7c8L8a+YNaf5EXYBAoGBAO2KxDggkcMpkNQlQZxEAM1YBPW7GpgEpYx8/VaM
                1SwlCtr/rSyluBBGoWqz9o3Lb8ngqd1eOy3rXUWkGic+63CULxWaNxy5wZcDYPVs
                FeELhZGtdmled50cB5hL2tgYY7nr0XIqi86ropoVfcxZ82p6xBPIYaCBzRKz6pt2
                quE9AoGBAOG96No+eiCk5Po++T3NfxU3Okc+frT5HRtzAvWf2rmIamw+IlCN9/sK
                0Yd/Wp1Dqb2RFWVainhTi7hW62hWssLacdnnil2di5zfyt/us1aCGRXzLwjv9rsg
                Kk55tArKF0njlmblQUbpgif96Ollsb3/pywDbej9lstYaSq8N9M1AoGBAJtkQ6hT
                5ga9kji1ho4rDjtGcTgvBd6ca4/T1AZiarFOKiPJTgf/AMHk8oNS5t8rTh3KElT1
                59DKP2HnUBSMXIhw57xB/fuUqMeZNjxWUJm/Z8k8qFGVsrncNDu0o5zpl5NwaLs+
                iebQ8LXLiVe9IDdvyAUI+JR/VR//AmJg5rghAoGAA0r95pEavvcoz+2zPQ+OVwTj
                OL7Uolcv8YKP/H1Ed4hh5QpS/dHUWDkkLVHSRJEEHNvM8BmOA4tUcm/yJyd8nBML
                rh4OiqcNrlAlaXbV7uEe9I8DlKHLe5dQhqyHz9B63n0PaJjXhu1JFMRDbYQqP5dH
                HQE/zTJFzNmRTypHtjECgYAlTin5zk7GWlzdE2fFLj+nfLVVJWMLOIEXu48JIr4f
                qCZwJBEYhBfeA+NRGCv5EybVKwICfnoivNuKsm+op/vGF6cL5+Z3TFiGVtionR7E
                vp+3vzdS/pgnqxr8E87/x59tdshBhvHM8J1TpqBwTXSZdlRjYgXoBem6x2zDpw7R
                uzCCAx0wggGKAoGBAM2yCoZ51QdQdbwKfyuUZFQhVXZX6M0RNINhkzHLJCuBmF38
                jP76vOfEQNRIwn0iRiqduQNOE1y/5cPMevao70MyTVmeasvHj9b+zgS7M4fMO6Bz
                v2q/Cmm2qFkCiiz6YvGuISvxJJzJrrVeBRExhHd49bLBvxJEZQK/siYyMEFlAoGA
                L7T7e/UF04x1wgctN45TNrAEgk4hUG6NH2uiGApleTG1hRbuHLVK2vZJkvLNKPiq
                DXhHUNzq4LghMiha3JqR46PnDMIRQvImCldOsQo6CWT072HpI3jrkVkr8nkEUyo/
                iI46Y1aqhzK/spD72+EAODV1xt/o0PPL+bc8Ol+pkYECgYAQWs2+zl1PoVbJjmvw
                NAA3NVbWTjlxvfGpxhtzVyGBhQ0438ZP8iq5C4b2Xj4hYhzj4UfO/+isbFmNApAX
                pDNa14BkowFVJlmkLEz/+xYUnPI2dCaHPAGW6xFCNujpVa+xoer6WMwtnds0+uPk
                5YboHW2AAO3XOgBgXE5gsKJ6/jCCAYsCgYEA8TMRmSPxuOCRny1+Hfdfk0/jUJV4
                PEsCU777c967nP4ietNh/4c/vcch45TT1kJAsBlv5ZaTuChzkbwOKuxIY7HP0csM
                0A4khjXakSERr6a19TD9bTIUlrKgwjW2ytn7BtSXhvdixUdZ8RTssRylM6c7k6qw
                M6XuMX7IgRBaZo8CgYAufnKg+33H7noDnghWjG2+/sJJsVZJAQiEzia4cjHmFFLf
                LEoSsKaH1Y/hx7mB7ql7iJu6POlisWF9sStl+MAHf6oYvbRNkrxVpqHoIeC/5Dnk
                9rmTR/kSB4LXjPUcayJpcad3284NSzC6ORdbGLN7nnvsfhWTDyQ4JEFQJ6/VXwKB
                gQCYAum4G/JraK2tNbb5675HI54WQQ2SL9nHJu3FuQEMwk+7+wTPiu/c0xoU3xRm
                govt4vzw2tQujvTjktt/2ReSs0mOEOjwA0rnxbjI0qHJeq9VCiYjdBCTdVqHSmCy
                FHefwfrcV2upUj1wTMf2eTezb1THuiVN1aaLLjthFT/Q1Q==
                -----END PRIVATE KEY-----
            """.trimIndent()
        )
        rsa.forEach {
            CryptoPrivateKey.decodeFromPem(it).getOrThrow()
        }
    }
})