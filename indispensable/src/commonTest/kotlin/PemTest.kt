import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.asn1.decodeFromPem
import at.asitplus.signum.indispensable.asn1.encodeToPEM
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.types.shouldBeInstanceOf

@OptIn(ExperimentalStdlibApi::class)
class PemTest : FreeSpec({
    "SEC1" {
        val sec1 = """
            -----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIGwHU3LKj2fCxiUWB76jCnxIOJ2KAgYKbYGays8h/g+goAoGCCqGSM49
            AwEHoUQDQgAET+Zr8vrF+kdr1zpjK3ufUv1fd7DS0s8Yf8/Ny3Hb4I57Sz20Zabp
            brDmqFB7AmrWhdejOPHn9+Ln51i42bCdGQ==
            -----END EC PRIVATE KEY-----
        """.trimIndent()

        val key = CryptoPrivateKey.EC.decodeFromPem(sec1).getOrThrow()
        key.isDestroyed() shouldBe false
        key.pemEncodeSec1(destroySource = false).getOrThrow()
        key.isDestroyed() shouldBe false
        key.pemEncodeSec1(destroySource = true).getOrThrow() shouldBe sec1
        key.isDestroyed() shouldBe true
        (CryptoPrivateKey.decodeFromPem(sec1).getOrThrow() as CryptoPrivateKey.EC).pemEncodeSec1()
            .getOrThrow() shouldBe sec1
    }

    "PKCS#8" {
        val pkcs8 = """
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbAdTcsqPZ8LGJRYH
            vqMKfEg4nYoCBgptgZrKzyH+D6ChRANCAARP5mvy+sX6R2vXOmMre59S/V93sNLS
            zxh/z83LcdvgjntLPbRlpulusOaoUHsCataF16M48ef34ufnWLjZsJ0Z
            -----END PRIVATE KEY-----
        """.trimIndent()
        val key = CryptoPrivateKey.decodeFromPem(pkcs8).getOrThrow()
        key.isDestroyed() shouldBe false
        key.encodeToPEM(destroySource = false).getOrThrow()
        key.isDestroyed() shouldBe false
        key.encodeToPEM(destroySource = true).getOrThrow() shouldBe pkcs8
        key.isDestroyed() shouldBe true
        key.encodeToPEM().isSuccess shouldBe false
    }

    "from iOS" {
        val rsa =
            "308206e40201000282018100984a14a911fd17685b69f6d41722a7d8250de916cf4acaf097ede373626a6c67284ef953692f43bd48b075890f70422822b9254f9a1ac7038b97e3da6ee0efa080fe16cb7355c0b43f4df77634a8c943745b2313e46ff28c4377576fb934bb2a099a81dea9c69335a52f2b5e7c357f608cd9a7d6d71f7e3932f2df46ff704c279418807fdd179a75e930f61b9e4c27b003d63f7f562d71db128d8735f75cdd907706b5630b7e69a31357d816b73d2807c5bf90cc10a6d7d04088d4d80116be7119fdf8676e50557da72afe20543dfe6acc35b12614ca45780c3e5670c63c3a18fe937fbb0bf7284eac03d4b80d600ee1bdb7e536d0d590baffaed3bcd9f873a5591d6faeaeae4d0058114946df844bc3125a51310de06149a97fdb929a8938255ac4a5bf070fcc932b37ef94b639cafff7dc4e3a901c7bfa69b1cd8bd8dfb86a1967b6b9cdc2307020feef9ce6534d1b22f8f5a00761d6f7308b8d3de0e043be14aa57f1afa112daf0b8b8c48473e21db1ec48dd848bed0aa243e7f833cfbbd9020301000102820180399450e977e6b491fd763c2006bb50b0d599c3d69efbcd6d5854569a4acca83dfcac97726523bcbdf59cda63bf1597bdeb1b0bb36435d9a74a815c623b680ad229d36834f65fa6e3bfc7afd7dea32eadb571bbfa8a7595445941e72a53e14f1eded0af67cbd34bd78da41f06b379dab65baaf3ddb42ab123d952a0ff0c179e839c680335d517568c5c65e9b7998b7bb9fe49646ab5dfaadbc4d1041d7070894954e7916f686a1c70cf2078906629d657d1f9d33a84d54065f9f0826145501f22b8f5f005fc30f9de4bcb85db21305c2b3445c820122e86ceaf76e033791d855e07f49d9685a0e6e3d148cdad95737e476021293e406e0f3b055ddd5f7222f5b85e18082cf17adbc22b50d56f913fb12c368f7ad0ef865227009781151b6539473cbaa38d5de790f3fcfd23ff7639d8a5ecd313dcc41f0531c4d52e69932e455cbb8840929f17fbbf92af0e4461a43d18db317703896dd1a2ce5c886d63bc4070a2735bf13b863f0159e7ce2200ccf01f20a66068557ebe42457e477b3eb3be3d0281c100c9393384e03e878b1bd4abcf42914ebd050b467a69522ad8794ce5f4686ec2d44ba0ca750f55d9e6c86e6d42594de45a0e8df58bb5ff9787cbdbafc1a80026ce82cc9676b29f04efcd1f059d402e138b25040313fd7f09cf3706e7cf9f9182eca36d25a03aff6efe5826de3b7e2eff8e46b841bb37af98c9e6cff12ff4ae317ebb172f531dfd98948e39f8b3423345f39259791bf18f2f31a2541a86a6f4125b61b1b84090c752e522936c27688f9f7c1838896364d09b603a69d4c5d4cdec370281c100c1bec6ee6f0b83181a2626716fc70ef57667e4f181a44a8c5591b91c879d11a76ea417662017da58b886cbc88740bb72eca3d78fa5c4b15054a3644fab51490df79177db43b5a254438be770e57692ae393bf77880c84e9c5628ce1ba38d0261a8beb27c47d57d20a3927d0be05374cc308407b48ff0124828cdce1d543d0285fcf912b86bd2a7e037cba8e2cd7ee495bedcda334f72858c420cefd6d9497e4b0a9f4b897ebb0f7178e12f3675225f7f0e071716f7013bd09279258f79a4306f0281c100a56b74c2e366041f83bd8d9050f50b79b04fd89c81409f205e77ad0303672a9b43a0e74edc50835589a7de0211504b4d0d71fe4de04c41d1ccf0c8c7b6c8891e73c0a460e7ee7a2c78bfebe99dfd42ebbc7e53d977279c74d093c8b59244191158383e1a3ee605e4e9aaea3e963924b55dc5d3a388dfbe071ccc0d46932b305d328898cb0778969a696196e626a1e7fb98701d73af5d3a3adf6bac72cd8510223769d6429dc27e8f07a191e3c3bd6e2aa1eeb8631159bca19ae3ad9b049a54790281c10094dffacec6a76af1bf4e27662d45217a7ea4b0e8defc9688254c979893a09f2b303a88fc6196d2a23010ec504795f734052095087d9199caa76ef22ac1f2f116f9705f502e4448db4518211cc0460fca2e92a4c384f9e665fd52d7a5a754384b40b660425d946fd4ffbc15b86584db8ff78bccbbf38abf1191c12b2ba04a4d411635722c223639e772185dcb01ab0b0d021f84cfbeb1ba6b1f69ff75f17ba6bf150778accba403e6e6c2ea5b8740856f05216f9da6e9dcc39579dfe1d2cfd6a30281c06c970f100b9ac4f229ad5301728cbd2d4d10fabf961d427add4852e2553f1849ad4889c7fb3b22c2a47d28f95d56ed9635de37a74f148a8dd46da4eeebbc176470972d8dfdfe0fdb65100107cd7c7f7933de512e531118947ed8602d3582753939269c766010577995f5398dd0ae572a2721b8a606a71035a2441cdb1a0a289ec45dd2566d9985f17e1d6f468e5b22a7e399eac5f233500864a141634ee5c34ac16bf6ceb153e2cc6533ee77096c7693a1c2f3bb6352d2562d070ff55d3070b1"
        val ec = listOf(
            "044a58f643eaaf0a2b92e3dfae095838895833449bc2b35b77780e64c134b788c604d9e617ad2b1b1a54e196990f641a069b02d9ae418662194605b204ac134a5ce854127f57a280a012f31930b0acfc41e2bf6afb95c403126da04510ec1f6470452d54594d86e80a88163b80d681f09defd1999c8b4d483f8ef7f7f16f7060e549a76cdae2e241afb9d873f0ede30ab8",
            "04810efff4ab927d512e59fc188af66ce358a8507193e07234109b7a30897efae4baea616cd39a0e838ef691941ac640ef2383069246e9b4cb1795ab8d49b7a0c75ccdd0f2aa1dabeb708cd4cee9f6b26a689fe58ecba48619c80de73996d7a314",
            "04de2217560986e17cb2dda07fedb59055ba986f20162b9f59a3073c8188a9c44618e6c032e5ea41296550a5b5d88975bbb622a83b4658b4659e2e072aa60c593846122445185002b83011c28a2dc85bbcf407a3938dfcb8c9140632cd276df422965910dc5db2e4c7e17fe5fe7bd488014919bdb6a5f7ce497d89d0eed815ebff8993db5052392c0e57cd11b1766a478f",
            "0401c40e2f75a36f7b755b25676c0cdc1d57135e608294b6e4113a6657175f2249e1b5ffca85a788e2ea4d80e7c0f3d92249c52cdb2a42b75c3c127e218926ee64c3ac01616ca696c9206f023ccb3f6cfdb1211c43acaffee4ff9de2480f5c6010ef1fe2eda0a99d3a7f75089085cc57d18651c6bd7e9607336dbf983a9131b4f27c11d1e300eae3316d84dfa529157b57517dfd70de9f11568f22b3967689bff5dd5fe6b2f155d117939bbe55257711977170d762c4334be1968e61c3f02b8f57f34193e5611f",
            "0401e8a1af9610024a8b28af1e619022735c1d42c58780f69b0a5abbe25643e1257e09d3550a2b3c12440ada7574cfa107002eb6f0b87fe8c1ee1f2d7af526a282321900cc9af4b002828883dfb0eabac34f2dd021bf26781e11d547a9bad0c185c7f9d2ab2a62622b5e1202ba68838b7ef1511cb378db70db8e5a27efa23071b92b1efbf900b5875b2d1458c7f03877b5e2dc8adb8111763e4534a4270f3c34ecbd8a779522f94f72358b61742ac0f68175a17e37369b1a80bc89c96862f179c4ea4b5998c20f",
            "049d22ada3fed52d17e890066b707ba9476e4088b2d89e09109ee71a7590e629677f7bf1958e20533a41eaa4c26d371345b68e39b59ae1a36536c0ffa28ad976da0ba7b225d48c46e30e4fc6dbe05b590179f2c6bae0b9714f17c6b1996552dd6a"
        )

        val rsaKey = CryptoPrivateKey.fromIosEncoded(rsa.hexToByteArray()).getOrThrow()
        rsaKey.shouldBeInstanceOf<CryptoPrivateKey.RSA>()

        rsaKey.encodeToPEM(destroySource = false).getOrThrow() shouldNotContain "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        rsaKey.isDestroyed() shouldBe false
        rsaKey.privateExponent.isDestroyed() shouldBe false
        rsaKey.exponent1.isDestroyed() shouldBe false
        rsaKey.exponent2.isDestroyed() shouldBe false
        rsaKey.coefficient.isDestroyed() shouldBe false

        rsaKey.encodeToPEM(destroySource = true).getOrThrow() shouldNotContain "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        rsaKey.isDestroyed() shouldBe true
        rsaKey.privateExponent.isDestroyed() shouldBe true
        rsaKey.exponent1.isDestroyed() shouldBe true
        rsaKey.exponent2.isDestroyed() shouldBe true
        rsaKey.coefficient.isDestroyed() shouldBe true


        ec.forEach { string ->
        val key = CryptoPrivateKey.fromIosEncoded(string.hexToByteArray()).getOrThrow()
            key.shouldBeInstanceOf<CryptoPrivateKey.EC>()
            key.encodeToPEM(destroySource = false).getOrThrow() shouldNotContain "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            key.isDestroyed() shouldBe false

            key.encodeToPEM(destroySource = true).getOrThrow() shouldNotContain "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            key.isDestroyed() shouldBe true
            key.encodeToPEM().isSuccess shouldBe false

        }

    }
})