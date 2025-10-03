package at.asitplus.signum.ecmath

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.supreme.azString
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import com.ionspin.kotlin.bignum.integer.BigInteger
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.testSuite
import io.kotest.core.names.TestNameBuilder
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int
import io.kotest.property.checkAll
import kotlin.math.min
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

val RFC9380Test by testSuite(testConfig = TestConfig.testScope(isEnabled = true, timeout = 20.minutes)) {
    "Assumption: all implemented curves have AB > 0" - {
        withData(ECCurve.entries) { crv ->
            /* map_to_curve_simple_swu in RFC9380.kt depends on this */
            crv.a shouldNotBe BigInteger.ZERO
            crv.b shouldNotBe BigInteger.ZERO
        }
    }
    "Assumption: all implemented curves have q = 3 (mod 4)" - {
        withData(ECCurve.entries) { crv ->
            /* the sqrt and sqrt_ratio implementations in RFC9380.kt depend on this */
            crv.modulus.mod(BigInteger(4)) shouldBe BigInteger(3)
        }
    }
    "RFC 9380 Appendix J. Test Vectors" - {
        data class SuiteTestInfo(
            val suiteName: String, val suiteRef: (ByteArray) -> RFC9380.HashToEllipticCurve,
            val curve: ECCurve, val dst: String, val tests: String
        ) {
            val dstB get() = dst.encodeToByteArray()
        }

        val testcasePattern = Regex(
            "msg\\s+=([\\x00-\\xff]+?)" +
                    "P\\.x\\s+=\\s+([0-9a-f\\s]+?)" +
                    "P\\.y\\s+=\\s+([0-9a-f\\s]+?)" +
                    "u\\[0]\\s+=\\s+([0-9a-f\\s]+?)" +
                    "(?:u\\[1]\\s+=\\s+([0-9a-f\\s]+?))?" +
                    "Q0?\\.x\\s+=\\s+([0-9a-f\\s]+?)" +
                    "Q0?\\.y\\s+=(?:\\s+([0-9a-f\\s]+?)" +
                    "Q1?\\.x\\s+=\\s+([0-9a-f\\s]+?)" +
                    "Q1?\\.y\\s+=)?\\s+([0-9a-f\\s]+)"
        )
        val whitespacePattern = Regex("\\s")
        withDataSuites(
            nameFn = SuiteTestInfo::suiteName, sequenceOf(
                SuiteTestInfo(
                    suiteName = "P256_XMD:SHA-256_SSWU_RO_", suiteRef = RFC9380::`P256_XMD∶SHA-256_SSWU_RO_`,
                    curve = ECCurve.SECP_256_R_1, dst = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_",
                    """
msg     =
P.x     = 2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91
          c44247d3e4
P.y     = 8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9a
          b5c43e8415
u[0]    = ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba1
          1582515009
u[1]    = 8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e
          220e2eea5a
Q0.x    = ab640a12220d3ff283510ff3f4b1953d09fad35795140b1c5d64f3
          13967934d5
Q0.y    = dccb558863804a881d4fff3455716c836cef230e5209594ddd33d8
          5c565b19b1
Q1.x    = 51cce63c50d972a6e51c61334f0f4875c9ac1cd2d3238412f84e31
          da7d980ef5
Q1.y    = b45d1a36d00ad90e5ec7840a60a4de411917fbe7c82c3949a6e699
          e5a1b66aac

msg     = abc
P.x     = 0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775da
          c4a3388a0f
P.y     = 5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71
          ffd424212e
u[0]    = afe47f2ea2b10465cc26ac403194dfb68b7f5ee865cda61e9f3e07
          a537220af1
u[1]    = 379a27833b0bfe6f7bdca08e1e83c760bf9a338ab335542704edcd
          69ce9e46e0
Q0.x    = 5219ad0ddef3cc49b714145e91b2f7de6ce0a7a7dc7406c7726c7e
          373c58cb48
Q0.y    = 7950144e52d30acbec7b624c203b1996c99617d0b61c2442354301
          b191d93ecf
Q1.x    = 019b7cb4efcfeaf39f738fe638e31d375ad6837f58a852d032ff60
          c69ee3875f
Q1.y    = 589a62d2b22357fed5449bc38065b760095ebe6aeac84b01156ee4
          252715446e

msg     = abcdef0123456789
P.x     = 65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c15268118
          64e544ed80
P.y     = cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d
          6df9b56ca3
u[0]    = 0fad9d125a9477d55cf9357105b0eb3a5c4259809bf87180aa01d6
          51f53d312c
u[1]    = b68597377392cd3419d8fcc7d7660948c8403b19ea78bbca4b133c
          9d2196c0fb
Q0.x    = a17bdf2965eb88074bc01157e644ed409dac97cfcf0c61c998ed0f
          a45e79e4a2
Q0.y    = 4f1bc80c70d411a3cc1d67aeae6e726f0f311639fee560c7f5a664
          554e3c9c2e
Q1.x    = 7da48bb67225c1a17d452c983798113f47e438e4202219dd0715f8
          419b274d66
Q1.y    = b765696b2913e36db3016c47edb99e24b1da30e761a8a3215dc0ec
          4d8f96e6f9

msg     = q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
          qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
          qqqqqqqqqqqqqqqqqqqqqqqqq
P.x     = 4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b07853
          3dc65a0b5d
P.y     = 98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539
          d2bfb3c29e
u[0]    = 3bbc30446f39a7befad080f4d5f32ed116b9534626993d2cc5033f
          6f8d805919
u[1]    = 76bb02db019ca9d3c1e02f0c17f8baf617bbdae5c393a81d9ce11e
          3be1bf1d33
Q0.x    = c76aaa823aeadeb3f356909cb08f97eee46ecb157c1f56699b5efe
          bddf0e6398
Q0.y    = 776a6f45f528a0e8d289a4be12c4fab80762386ec644abf2bffb9b
          627e4352b1
Q1.x    = 418ac3d85a5ccc4ea8dec14f750a3a9ec8b85176c95a7022f39182
          6794eb5a75
Q1.y    = fd6604f69e9d9d2b74b072d14ea13050db72c932815523305cb9e8
          07cc900aff

msg     = a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
P.x     = 457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5
          e49cd64bc5
P.y     = ecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa6
          2b0f4757dc
u[0]    = 4ebc95a6e839b1ae3c63b847798e85cb3c12d3817ec6ebc10af6ee
          51adb29fec
u[1]    = 4e21af88e22ea80156aff790750121035b3eefaa96b425a8716e0d
          20b4e269ee
Q0.x    = d88b989ee9d1295df413d4456c5c850b8b2fb0f5402cc5c4c7e815
          412e926db8
Q0.y    = bb4a1edeff506cf16def96afff41b16fc74f6dbd55c2210e5b8f01
          1ba32f4f40
Q1.x    = a281e34e628f3a4d2a53fa87ff973537d68ad4fbc28d3be5e8d9f6
          a2571c5a4b
Q1.y    = f6ed88a7aab56a488100e6f1174fa9810b47db13e86be999644922
          961206e184"""
                ),
                SuiteTestInfo(
                    suiteName = "P256_XMD:SHA-256_SSWU_NU_", suiteRef = RFC9380::`P256_XMD∶SHA-256_SSWU_NU_`,
                    curve = ECCurve.SECP_256_R_1, dst = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_NU_",
                    """
msg     =
P.x     = f871caad25ea3b59c16cf87c1894902f7e7b2c822c3d3f73596c5a
          ce8ddd14d1
P.y     = 87b9ae23335bee057b99bac1e68588b18b5691af476234b8971bc4
          f011ddc99b
u[0]    = b22d487045f80e9edcb0ecc8d4bf77833e2bf1f3a54004d7df1d57
          f4802d311f
Q.x     = f871caad25ea3b59c16cf87c1894902f7e7b2c822c3d3f73596c5a
          ce8ddd14d1
Q.y     = 87b9ae23335bee057b99bac1e68588b18b5691af476234b8971bc4
          f011ddc99b

msg     = abc
P.x     = fc3f5d734e8dce41ddac49f47dd2b8a57257522a865c124ed02b92
          b5237befa4
P.y     = fe4d197ecf5a62645b9690599e1d80e82c500b22ac705a0b421fac
          7b47157866
u[0]    = c7f96eadac763e176629b09ed0c11992225b3a5ae99479760601cb
          d69c221e58
Q.x     = fc3f5d734e8dce41ddac49f47dd2b8a57257522a865c124ed02b92
          b5237befa4
Q.y     = fe4d197ecf5a62645b9690599e1d80e82c500b22ac705a0b421fac
          7b47157866

msg     = abcdef0123456789
P.x     = f164c6674a02207e414c257ce759d35eddc7f55be6d7f415e2cc17
          7e5d8faa84
P.y     = 3aa274881d30db70485368c0467e97da0e73c18c1d00f34775d012
          b6fcee7f97
u[0]    = 314e8585fa92068b3ea2c3bab452d4257b38be1c097d58a2189045
          6c2929614d
Q.x     = f164c6674a02207e414c257ce759d35eddc7f55be6d7f415e2cc17
          7e5d8faa84
Q.y     = 3aa274881d30db70485368c0467e97da0e73c18c1d00f34775d012
          b6fcee7f97

msg     = q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
          qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
          qqqqqqqqqqqqqqqqqqqqqqqqq
P.x     = 324532006312be4f162614076460315f7a54a6f85544da773dc659
          aca0311853
P.y     = 8d8197374bcd52de2acfefc8a54fe2c8d8bebd2a39f16be9b710e4
          b1af6ef883
u[0]    = 752d8eaa38cd785a799a31d63d99c2ae4261823b4a367b133b2c66
          27f48858ab
Q.x     = 324532006312be4f162614076460315f7a54a6f85544da773dc659
          aca0311853
Q.y     = 8d8197374bcd52de2acfefc8a54fe2c8d8bebd2a39f16be9b710e4
          b1af6ef883

msg     = a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
P.x     = 5c4bad52f81f39c8e8de1260e9a06d72b8b00a0829a8ea004a610b
          0691bea5d9
P.y     = c801e7c0782af1f74f24fc385a8555da0582032a3ce038de637ccd
          cb16f7ef7b
u[0]    = 0e1527840b9df2dfbef966678ff167140f2b27c4dccd884c25014d
          ce0e41dfa3
Q.x     = 5c4bad52f81f39c8e8de1260e9a06d72b8b00a0829a8ea004a610b
          0691bea5d9
Q.y     = c801e7c0782af1f74f24fc385a8555da0582032a3ce038de637ccd
          cb16f7ef7b"""
                ),
                SuiteTestInfo(
                    suiteName = "P384_XMD:SHA-384_SSWU_RO_", suiteRef = RFC9380::`P384_XMD∶SHA-384_SSWU_RO_`,
                    curve = ECCurve.SECP_384_R_1, dst = "QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_",
                    """
msg     =
P.x     = eb9fe1b4f4e14e7140803c1d99d0a93cd823d2b024040f9c067a8e
          ca1f5a2eeac9ad604973527a356f3fa3aeff0e4d83
P.y     = 0c21708cff382b7f4643c07b105c2eaec2cead93a917d825601e63
          c8f21f6abd9abc22c93c2bed6f235954b25048bb1a
u[0]    = 25c8d7dc1acd4ee617766693f7f8829396065d1b447eedb155871f
          effd9c6653279ac7e5c46edb7010a0e4ff64c9f3b4
u[1]    = 59428be4ed69131df59a0c6a8e188d2d4ece3f1b2a3a02602962b4
          7efa4d7905945b1e2cc80b36aa35c99451073521ac
Q0.x    = e4717e29eef38d862bee4902a7d21b44efb58c464e3e1f0d03894d
          94de310f8ffc6de86786dd3e15a1541b18d4eb2846
Q0.y    = 6b95a6e639822312298a47526bb77d9cd7bcf76244c991c8cd7007
          5e2ee6e8b9a135c4a37e3c0768c7ca871c0ceb53d4
Q1.x    = 509527cfc0750eedc53147e6d5f78596c8a3b7360e0608e2fab056
          3a1670d58d8ae107c9f04bcf90e89489ace5650efd
Q1.y    = 33337b13cb35e173fdea4cb9e8cce915d836ff57803dbbeb7998aa
          49d17df2ff09b67031773039d09fbd9305a1566bc4

msg     = abc
P.x     = e02fc1a5f44a7519419dd314e29863f30df55a514da2d655775a81
          d413003c4d4e7fd59af0826dfaad4200ac6f60abe1
P.y     = 01f638d04d98677d65bef99aef1a12a70a4cbb9270ec55248c0453
          0d8bc1f8f90f8a6a859a7c1f1ddccedf8f96d675f6
u[0]    = 53350214cb6bef0b51abb791b1c4209a2b4c16a0c67e1ab1401017
          fad774cd3b3f9a8bcdf7f6229dd8dd5a075cb149a0
u[1]    = c0473083898f63e03f26f14877a2407bd60c75ad491e7d26cbc6cc
          5ce815654075ec6b6898c7a41d74ceaf720a10c02e
Q0.x    = fc853b69437aee9a19d5acf96a4ee4c5e04cf7b53406dfaa2afbdd
          7ad2351b7f554e4bbc6f5db4177d4d44f933a8f6ee
Q0.y    = 7e042547e01834c9043b10f3a8221c4a879cb156f04f72bfccab0c
          047a304e30f2aa8b2e260d34c4592c0c33dd0c6482
Q1.x    = 57912293709b3556b43a2dfb137a315d256d573b82ded120ef8c78
          2d607c05d930d958e50cb6dc1cc480b9afc38c45f1
Q1.y    = de9387dab0eef0bda219c6f168a92645a84665c4f2137c14270fb4
          24b7532ff84843c3da383ceea24c47fa343c227bb8

msg     = abcdef0123456789
P.x     = bdecc1c1d870624965f19505be50459d363c71a699a496ab672f9a
          5d6b78676400926fbceee6fcd1780fe86e62b2aa89
P.y     = 57cf1f99b5ee00f3c201139b3bfe4dd30a653193778d89a0accc5e
          0f47e46e4e4b85a0595da29c9494c1814acafe183c
u[0]    = aab7fb87238cf6b2ab56cdcca7e028959bb2ea599d34f68484139d
          de85ec6548a6e48771d17956421bdb7790598ea52e
u[1]    = 26e8d833552d7844d167833ca5a87c35bcfaa5a0d86023479fb28e
          5cd6075c18b168bf1f5d2a0ea146d057971336d8d1
Q0.x    = 0ceece45b73f89844671df962ad2932122e878ad2259e650626924
          e4e7f132589341dec1480ebcbbbe3509d11fb570b7
Q0.y    = fafd71a3115298f6be4ae5c6dfc96c400cfb55760f185b7b03f3fa
          45f3f91eb65d27628b3c705cafd0466fafa54883ce
Q1.x    = dea1be8d3f9be4cbf4fab9d71d549dde76875b5d9b876832313a08
          3ec81e528cbc2a0a1d0596b3bcb0ba77866b129776
Q1.y    = eb15fe71662214fb03b65541f40d3eb0f4cf5c3b559f647da138c9
          f9b7484c48a08760e02c16f1992762cb7298fa52cf

msg     = q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
          qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
          qqqqqqqqqqqqqqqqqqqqqqqqq
P.x     = 03c3a9f401b78c6c36a52f07eeee0ec1289f178adf78448f43a385
          0e0456f5dd7f7633dd31676d990eda32882ab486c0
P.y     = cc183d0d7bdfd0a3af05f50e16a3f2de4abbc523215bf57c848d5e
          a662482b8c1f43dc453a93b94a8026db58f3f5d878
u[0]    = 04c00051b0de6e726d228c85bf243bf5f4789efb512b22b498cde3
          821db9da667199b74bd5a09a79583c6d353a3bb41c
u[1]    = 97580f218255f899f9204db64cd15e6a312cb4d8182375d1e5157c
          8f80f41d6a1a4b77fb1ded9dce56c32058b8d5202b
Q0.x    = 051a22105e0817a35d66196338c8d85bd52690d79bba373ead8a86
          dd9899411513bb9f75273f6483395a7847fb21edb4
Q0.y    = f168295c1bbcff5f8b01248e9dbc885335d6d6a04aea960f7384f7
          46ba6502ce477e624151cc1d1392b00df0f5400c06
Q1.x    = 6ad7bc8ed8b841efd8ad0765c8a23d0b968ec9aa360a558ff33500
          f164faa02bee6c704f5f91507c4c5aad2b0dc5b943
Q1.y    = 47313cc0a873ade774048338fc34ca5313f96bbf6ae22ac6ef475d
          85f03d24792dc6afba8d0b4a70170c1b4f0f716629

msg     = a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
P.x     = 7b18d210b1f090ac701f65f606f6ca18fb8d081e3bc6cbd937c560
          4325f1cdea4c15c10a54ef303aabf2ea58bd9947a4
P.y     = ea857285a33abb516732915c353c75c576bf82ccc96adb63c094dd
          e580021eddeafd91f8c0bfee6f636528f3d0c47fd2
u[0]    = 480cb3ac2c389db7f9dac9c396d2647ae946db844598971c26d1af
          d53912a1491199c0a5902811e4b809c26fcd37a014
u[1]    = d28435eb34680e148bf3908536e42231cba9e1f73ae2c6902a222a
          89db5c49c97db2f8fa4d4cd6e424b17ac60bdb9bb6
Q0.x    = 42e6666f505e854187186bad3011598d9278b9d6e3e4d2503c3d23
          6381a56748dec5d139c223129b324df53fa147c4df
Q0.y    = 8ee51dbda46413bf621838cc935d18d617881c6f33f3838a79c767
          a1e5618e34b22f79142df708d2432f75c7366c8512
Q1.x    = 4ff01ceeba60484fa1bc0d825fe1e5e383d8f79f1e5bb78e5fb26b
          7a7ef758153e31e78b9d60ce75c5e32e43869d4e12
Q1.y    = 0f84b978fac8ceda7304b47e229d6037d32062e597dc7a9b95bcd9
          af441f3c56c619a901d21635f9ec6ab4710b9fcd0e"""
                ),
                SuiteTestInfo(
                    suiteName = "P384_XMD:SHA-384_SSWU_NU_", suiteRef = RFC9380::`P384_XMD∶SHA-384_SSWU_NU_`,
                    curve = ECCurve.SECP_384_R_1, dst = "QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_NU_",
                    """
msg     =
P.x     = de5a893c83061b2d7ce6a0d8b049f0326f2ada4b966dc7e7292725
          6b033ef61058029a3bfb13c1c7ececd6641881ae20
P.y     = 63f46da6139785674da315c1947e06e9a0867f5608cf24724eb379
          3a1f5b3809ee28eb21a0c64be3be169afc6cdb38ca
u[0]    = bc7dc1b2cdc5d588a66de3276b0f24310d4aca4977efda7d6272e1
          be25187b001493d267dc53b56183c9e28282368e60
Q.x     = de5a893c83061b2d7ce6a0d8b049f0326f2ada4b966dc7e7292725
          6b033ef61058029a3bfb13c1c7ececd6641881ae20
Q.y     = 63f46da6139785674da315c1947e06e9a0867f5608cf24724eb379
          3a1f5b3809ee28eb21a0c64be3be169afc6cdb38ca

msg     = abc
P.x     = 1f08108b87e703c86c872ab3eb198a19f2b708237ac4be53d7929f
          b4bd5194583f40d052f32df66afe5249c9915d139b
P.y     = 1369dc8d5bf038032336b989994874a2270adadb67a7fcc32f0f88
          24bc5118613f0ac8de04a1041d90ff8a5ad555f96c
u[0]    = 9de6cf41e6e41c03e4a7784ac5c885b4d1e49d6de390b3cdd5a1ac
          5dd8c40afb3dfd7bb2686923bab644134483fc1926
Q.x     = 1f08108b87e703c86c872ab3eb198a19f2b708237ac4be53d7929f
          b4bd5194583f40d052f32df66afe5249c9915d139b
Q.y     = 1369dc8d5bf038032336b989994874a2270adadb67a7fcc32f0f88
          24bc5118613f0ac8de04a1041d90ff8a5ad555f96c

msg     = abcdef0123456789
P.x     = 4dac31ec8a82ee3c02ba2d7c9fa431f1e59ffe65bf977b948c59e1
          d813c2d7963c7be81aa6db39e78ff315a10115c0d0
P.y     = 845333cdb5702ad5c525e603f302904d6fc84879f0ef2ee2014a6b
          13edd39131bfd66f7bd7cdc2d9ccf778f0c8892c3f
u[0]    = 84e2d430a5e2543573e58e368af41821ca3ccc97baba7e9aab51a8
          4543d5a0298638a22ceee6090d9d642921112af5b7
Q.x     = 4dac31ec8a82ee3c02ba2d7c9fa431f1e59ffe65bf977b948c59e1
          d813c2d7963c7be81aa6db39e78ff315a10115c0d0
Q.y     = 845333cdb5702ad5c525e603f302904d6fc84879f0ef2ee2014a6b
          13edd39131bfd66f7bd7cdc2d9ccf778f0c8892c3f

msg     = q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
          qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
          qqqqqqqqqqqqqqqqqqqqqqqqq
P.x     = 13c1f8c52a492183f7c28e379b0475486718a7e3ac1dfef39283b9
          ce5fb02b73f70c6c1f3dfe0c286b03e2af1af12d1d
P.y     = 57e101887e73e40eab8963324ed16c177d55eb89f804ec9df06801
          579820420b5546b579008df2145fd770f584a1a54c
u[0]    = 504e4d5a529333b9205acaa283107bd1bffde753898f7744161f7d
          d19ba57fbb6a64214a2e00ddd2613d76cd508ddb30
Q.x     = 13c1f8c52a492183f7c28e379b0475486718a7e3ac1dfef39283b9
          ce5fb02b73f70c6c1f3dfe0c286b03e2af1af12d1d
Q.y     = 57e101887e73e40eab8963324ed16c177d55eb89f804ec9df06801
          579820420b5546b579008df2145fd770f584a1a54c

msg     = a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
P.x     = af129727a4207a8cb9e9dce656d88f79fce25edbcea350499d65e9
          bf1204537bdde73c7cefb752a6ed5ebcd44e183302
P.y     = ce68a3d5e161b2e6a968e4ddaa9e51504ad1516ec170c7eef3ca6b
          5327943eca95d90b23b009ba45f58b72906f2a99e2
u[0]    = 7b01ce9b8c5a60d9fbc202d6dde92822e46915d8c17e03fcb92ece
          1ed6074d01e149fc9236def40d673de903c1d4c166
Q.x     = af129727a4207a8cb9e9dce656d88f79fce25edbcea350499d65e9
          bf1204537bdde73c7cefb752a6ed5ebcd44e183302
Q.y     = ce68a3d5e161b2e6a968e4ddaa9e51504ad1516ec170c7eef3ca6b
          5327943eca95d90b23b009ba45f58b72906f2a99e2"""
                ),
                SuiteTestInfo(
                    suiteName = "P521_XMD:SHA-512_SSWU_RO_", suiteRef = RFC9380::`P521_XMD∶SHA-512_SSWU_RO_`,
                    curve = ECCurve.SECP_521_R_1, dst = "QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_RO_",
                    """
msg     =
P.x     = 00fd767cebb2452030358d0e9cf907f525f50920c8f607889a6a35
          680727f64f4d66b161fafeb2654bea0d35086bec0a10b30b14adef
          3556ed9f7f1bc23cecc9c088
P.y     = 0169ba78d8d851e930680322596e39c78f4fe31b97e57629ef6460
          ddd68f8763fd7bd767a4e94a80d3d21a3c2ee98347e024fc73ee1c
          27166dc3fe5eeef782be411d
u[0]    = 01e5f09974e5724f25286763f00ce76238c7a6e03dc396600350ee
          2c4135fb17dc555be99a4a4bae0fd303d4f66d984ed7b6a3ba3860
          93752a855d26d559d69e7e9e
u[1]    = 00ae593b42ca2ef93ac488e9e09a5fe5a2f6fb330d18913734ff60
          2f2a761fcaaf5f596e790bcc572c9140ec03f6cccc38f767f1c197
          5a0b4d70b392d95a0c7278aa
Q0.x    = 00b70ae99b6339fffac19cb9bfde2098b84f75e50ac1e80d6acb95
          4e4534af5f0e9c4a5b8a9c10317b8e6421574bae2b133b4f2b8c6c
          e4b3063da1d91d34fa2b3a3c
Q0.y    = 007f368d98a4ddbf381fb354de40e44b19e43bb11a1278759f4ea7
          b485e1b6db33e750507c071250e3e443c1aaed61f2c28541bb54b1
          b456843eda1eb15ec2a9b36e
Q1.x    = 01143d0e9cddcdacd6a9aafe1bcf8d218c0afc45d4451239e821f5
          d2a56df92be942660b532b2aa59a9c635ae6b30e803c45a6ac8714
          32452e685d661cd41cf67214
Q1.y    = 00ff75515df265e996d702a5380defffab1a6d2bc232234c7bcffa
          433cd8aa791fbc8dcf667f08818bffa739ae25773b32073213cae9
          a0f2a917a0b1301a242dda0c

msg     = abc
P.x     = 002f89a1677b28054b50d15e1f81ed6669b5a2158211118ebdef8a
          6efc77f8ccaa528f698214e4340155abc1fa08f8f613ef14a04371
          7503d57e267d57155cf784a4
P.y     = 010e0be5dc8e753da8ce51091908b72396d3deed14ae166f66d8eb
          f0a4e7059ead169ea4bead0232e9b700dd380b316e9361cfdba55a
          08c73545563a80966ecbb86d
u[0]    = 003d00c37e95f19f358adeeaa47288ec39998039c3256e13c2a4c0
          0a7cb61a34c8969472960150a27276f2390eb5e53e47ab193351c2
          d2d9f164a85c6a5696d94fe8
u[1]    = 01f3cbd3df3893a45a2f1fecdac4d525eb16f345b03e2820d69bc5
          80f5cbe9cb89196fdf720ef933c4c0361fcfe29940fd0db0a5da6b
          afb0bee8876b589c41365f15
Q0.x    = 01b254e1c99c835836f0aceebba7d77750c48366ecb07fb658e4f5
          b76e229ae6ca5d271bb0006ffcc42324e15a6d3daae587f9049de2
          dbb0494378ffb60279406f56
Q0.y    = 01845f4af72fc2b1a5a2fe966f6a97298614288b456cfc385a425b
          686048b25c952fbb5674057e1eb055d04568c0679a8e2dda3158dc
          16ac598dbb1d006f5ad915b0
Q1.x    = 007f08e813c620e527c961b717ffc74aac7afccb9158cebc347d57
          15d5c2214f952c97e194f11d114d80d3481ed766ac0a3dba3eb73f
          6ff9ccb9304ad10bbd7b4a36
Q1.y    = 0022468f92041f9970a7cc025d71d5b647f822784d29ca7b3bc3b0
          829d6bb8581e745f8d0cc9dc6279d0450e779ac2275c4c3608064a
          d6779108a7828ebd9954caeb

msg     = abcdef0123456789
P.x     = 006e200e276a4a81760099677814d7f8794a4a5f3658442de63c18
          d2244dcc957c645e94cb0754f95fcf103b2aeaf94411847c24187b
          89fb7462ad3679066337cbc4
P.y     = 001dd8dfa9775b60b1614f6f169089d8140d4b3e4012949b52f98d
          b2deff3e1d97bf73a1fa4d437d1dcdf39b6360cc518d8ebcc0f899
          018206fded7617b654f6b168
u[0]    = 00183ee1a9bbdc37181b09ec336bcaa34095f91ef14b66b1485c16
          6720523dfb81d5c470d44afcb52a87b704dbc5c9bc9d0ef524dec2
          9884a4795f55c1359945baf3
u[1]    = 00504064fd137f06c81a7cf0f84aa7e92b6b3d56c2368f0a08f447
          76aa8930480da1582d01d7f52df31dca35ee0a7876500ece3d8fe0
          293cd285f790c9881c998d5e
Q0.x    = 0021482e8622aac14da60e656043f79a6a110cbae5012268a62dd6
          a152c41594549f373910ebed170ade892dd5a19f5d687fae7095a4
          61d583f8c4295f7aaf8cd7da
Q0.y    = 0177e2d8c6356b7de06e0b5712d8387d529b848748e54a8bc0ef5f
          1475aa569f8f492fa85c3ad1c5edc51faf7911f11359bfa2a12d2e
          f0bd73df9cb5abd1b101c8b1
Q1.x    = 00abeafb16fdbb5eb95095678d5a65c1f293291dfd20a3751dbe05
          d0a9bfe2d2eef19449fe59ec32cdd4a4adc3411177c0f2dffd0159
          438706159a1bbd0567d9b3d0
Q1.y    = 007cc657f847db9db651d91c801741060d63dab4056d0a1d3524e2
          eb0e819954d8f677aa353bd056244a88f00017e00c3ce8beeedb43
          82d83d74418bd48930c6c182

msg     = q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
          qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
          qqqqqqqqqqqqqqqqqqqqqqqqq
P.x     = 01b264a630bd6555be537b000b99a06761a9325c53322b65bdc41b
          f196711f9708d58d34b3b90faf12640c27b91c70a507998e559406
          48caa8e71098bf2bc8d24664
P.y     = 01ea9f445bee198b3ee4c812dcf7b0f91e0881f0251aab272a1220
          1fd89b1a95733fd2a699c162b639e9acdcc54fdc2f6536129b6beb
          0432be01aa8da02df5e59aaa
u[0]    = 0159871e222689aad7694dc4c3480a49807b1eedd9c8cb4ae1b219
          d5ba51655ea5b38e2e4f56b36bf3e3da44a7b139849d28f598c816
          fe1bc7ed15893b22f63363c3
u[1]    = 004ef0cffd475152f3858c0a8ccbdf7902d8261da92744e98df9b7
          fadb0a5502f29c5086e76e2cf498f47321434a40b1504911552ce4
          4ad7356a04e08729ad9411f5
Q0.x    = 0005eac7b0b81e38727efcab1e375f6779aea949c3e409b53a1d37
          aa2acbac87a7e6ad24aafbf3c52f82f7f0e21b872e88c55e17b7fa
          21ce08a94ea2121c42c2eb73
Q0.y    = 00a173b6a53a7420dbd61d4a21a7c0a52de7a5c6ce05f31403bef7
          47d16cc8604a039a73bdd6e114340e55dacd6bea8e217ffbadfb8c
          292afa3e1b2afc839a6ce7bb
Q1.x    = 01881e3c193a69e4d88d8180a6879b74782a0bc7e529233e9f84bf
          7f17d2f319c36920ffba26f9e57a1e045cc7822c834c239593b6e1
          42a694aa00c757b0db79e5e8
Q1.y    = 01558b16d396d866e476e001f2dd0758927655450b84e12f154032
          c7c2a6db837942cd9f44b814f79b4d729996ced61eec61d85c6751
          39cbffe3fbf071d2c21cfecb

msg     = a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
P.x     = 00c12bc3e28db07b6b4d2a2b1167ab9e26fc2fa85c7b0498a17b03
          47edf52392856d7e28b8fa7a2dd004611159505835b687ecf1a764
          857e27e9745848c436ef3925
P.y     = 01cd287df9a50c22a9231beb452346720bb163344a41c5f5a24e83
          35b6ccc595fd436aea89737b1281aecb411eb835f0b939073fdd1d
          d4d5a2492e91ef4a3c55bcbd
u[0]    = 0033d06d17bc3b9a3efc081a05d65805a14a3050a0dd4dfb488461
          8eb5c73980a59c5a246b18f58ad022dd3630faa22889fbb8ba1593
          466515e6ab4aeb7381c26334
u[1]    = 0092290ab99c3fea1a5b8fb2ca49f859994a04faee3301cefab312
          d34227f6a2d0c3322cf76861c6a3683bdaa2dd2a6daa5d6906c663
          e065338b2344d20e313f1114
Q0.x    = 00041f6eb92af8777260718e4c22328a7d74203350c6c8f5794d99
          d5789766698f459b83d5068276716f01429934e40af3d1111a2278
          0b1e07e72238d2207e5386be
Q0.y    = 001c712f0182813942b87cab8e72337db017126f52ed797dd23458
          4ac9ae7e80dfe7abea11db02cf1855312eae1447dbaecc9d7e8c88
          0a5e76a39f6258074e1bc2e0
Q1.x    = 0125c0b69bcf55eab49280b14f707883405028e05c927cd7625d4e
          04115bd0e0e6323b12f5d43d0d6d2eff16dbcf244542f84ec05891
          1260dc3bb6512ab5db285fbd
Q1.y    = 008bddfb803b3f4c761458eb5f8a0aee3e1f7f68e9d7424405fa69
          172919899317fb6ac1d6903a432d967d14e0f80af63e7035aaae0c
          123e56862ce969456f99f102"""
                ),
                SuiteTestInfo(
                    suiteName = "P521_XMD:SHA-512_SSWU_NU_", suiteRef = RFC9380::`P521_XMD∶SHA-512_SSWU_NU_`,
                    curve = ECCurve.SECP_521_R_1, dst = "QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_NU_",
                    """
msg     =
P.x     = 01ec604b4e1e3e4c7449b7a41e366e876655538acf51fd40d08b97
          be066f7d020634e906b1b6942f9174b417027c953d75fb6ec64b8c
          ee2a3672d4f1987d13974705
P.y     = 00944fc439b4aad2463e5c9cfa0b0707af3c9a42e37c5a57bb4ecd
          12fef9fb21508568aedcdd8d2490472df4bbafd79081c81e99f4da
          3286eddf19be47e9c4cf0e91
u[0]    = 01e4947fe62a4e47792cee2798912f672fff820b2556282d9843b4
          b465940d7683a986f93ccb0e9a191fbc09a6e770a564490d2a4ae5
          1b287ca39f69c3d910ba6a4f
Q.x     = 01ec604b4e1e3e4c7449b7a41e366e876655538acf51fd40d08b97
          be066f7d020634e906b1b6942f9174b417027c953d75fb6ec64b8c
          ee2a3672d4f1987d13974705
Q.y     = 00944fc439b4aad2463e5c9cfa0b0707af3c9a42e37c5a57bb4ecd
          12fef9fb21508568aedcdd8d2490472df4bbafd79081c81e99f4da
          3286eddf19be47e9c4cf0e91

msg     = abc
P.x     = 00c720ab56aa5a7a4c07a7732a0a4e1b909e32d063ae1b58db5f0e
          b5e09f08a9884bff55a2bef4668f715788e692c18c1915cd034a6b
          998311fcf46924ce66a2be9a
P.y     = 003570e87f91a4f3c7a56be2cb2a078ffc153862a53d5e03e5dad5
          bccc6c529b8bab0b7dbb157499e1949e4edab21cf5d10b782bc1e9
          45e13d7421ad8121dbc72b1d
u[0]    = 0019b85ef78596efc84783d42799e80d787591fe7432dee1d9fa2b
          7651891321be732ddf653fa8fefa34d86fb728db569d36b5b6ed39
          83945854b2fc2dc6a75aa25b
Q.x     = 00c720ab56aa5a7a4c07a7732a0a4e1b909e32d063ae1b58db5f0e
          b5e09f08a9884bff55a2bef4668f715788e692c18c1915cd034a6b
          998311fcf46924ce66a2be9a
Q.y     = 003570e87f91a4f3c7a56be2cb2a078ffc153862a53d5e03e5dad5
          bccc6c529b8bab0b7dbb157499e1949e4edab21cf5d10b782bc1e9
          45e13d7421ad8121dbc72b1d

msg     = abcdef0123456789
P.x     = 00bcaf32a968ff7971b3bbd9ce8edfbee1309e2019d7ff373c3838
          7a782b005dce6ceffccfeda5c6511c8f7f312f343f3a891029c585
          8f45ee0bf370aba25fc990cc
P.y     = 00923517e767532d82cb8a0b59705eec2b7779ce05f9181c7d5d5e
          25694ef8ebd4696343f0bc27006834d2517215ecf79482a84111f5
          0c1bae25044fe1dd77744bbd
u[0]    = 01dba0d7fa26a562ee8a9014ebc2cca4d66fd9de036176aca8fc11
          ef254cd1bc208847ab7701dbca7af328b3f601b11a1737a899575a
          5c14f4dca5aaca45e9935e07
Q.x     = 00bcaf32a968ff7971b3bbd9ce8edfbee1309e2019d7ff373c3838
          7a782b005dce6ceffccfeda5c6511c8f7f312f343f3a891029c585
          8f45ee0bf370aba25fc990cc
Q.y     = 00923517e767532d82cb8a0b59705eec2b7779ce05f9181c7d5d5e
          25694ef8ebd4696343f0bc27006834d2517215ecf79482a84111f5
          0c1bae25044fe1dd77744bbd

msg     = q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
          qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
          qqqqqqqqqqqqqqqqqqqqqqqqq
P.x     = 001ac69014869b6c4ad7aa8c443c255439d36b0e48a0f57b03d6fe
          9c40a66b4e2eaed2a93390679a5cc44b3a91862b34b673f0e92c83
          187da02bf3db967d867ce748
P.y     = 00d5603d530e4d62b30fccfa1d90c2206654d74291c1db1c25b86a
          051ee3fffc294e5d56f2e776853406bd09206c63d40f37ad882952
          4cf89ad70b5d6e0b4a3b7341
u[0]    = 00844da980675e1244cb209dcf3ea0aabec23bd54b2cda69fff86e
          b3acc318bf3d01bae96e9cd6f4c5ceb5539df9a7ad7fcc5e9d5469
          6081ba9782f3a0f6d14987e3
Q.x     = 001ac69014869b6c4ad7aa8c443c255439d36b0e48a0f57b03d6fe
          9c40a66b4e2eaed2a93390679a5cc44b3a91862b34b673f0e92c83
          187da02bf3db967d867ce748
Q.y     = 00d5603d530e4d62b30fccfa1d90c2206654d74291c1db1c25b86a
          051ee3fffc294e5d56f2e776853406bd09206c63d40f37ad882952
          4cf89ad70b5d6e0b4a3b7341

msg     = a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
P.x     = 01801de044c517a80443d2bd4f503a9e6866750d2f94a22970f62d
          721f96e4310e4a828206d9cdeaa8f2d476705cc3bbc490a6165c68
          7668f15ec178a17e3d27349b
P.y     = 0068889ea2e1442245fe42bfda9e58266828c0263119f35a61631a
          3358330f3bb84443fcb54fcd53a1d097fccbe310489b74ee143fc2
          938959a83a1f7dd4a6fd395b
u[0]    = 01aab1fb7e5cd44ba4d9f32353a383cb1bb9eb763ed40b32bdd5f6
          66988970205998c0e44af6e2b5f6f8e48e969b3f649cae3c6ab463
          e1b274d968d91c02f00cce91
Q.x     = 01801de044c517a80443d2bd4f503a9e6866750d2f94a22970f62d
          721f96e4310e4a828206d9cdeaa8f2d476705cc3bbc490a6165c68
          7668f15ec178a17e3d27349b
Q.y     = 0068889ea2e1442245fe42bfda9e58266828c0263119f35a61631a
          3358330f3bb84443fcb54fcd53a1d097fccbe310489b74ee143fc2
          938959a83a1f7dd4a6fd395b"""
                )
            )
        )
        { suiteInfo ->
            val suite = suiteInfo.suiteRef(suiteInfo.dstB)

            class TestInfo private constructor(
                val msg: String, val Px: String, val Py: String,
                val u0: String, val u1: String?, val Q0x: String, val Q0y: String, val Q1x: String?, val Q1y: String?
            ) {
                constructor(match: MatchResult) :
                        this(
                            msg = match.groupValues[1].replace(whitespacePattern, ""),
                            Px = match.groupValues[2].replace(whitespacePattern, ""),
                            Py = match.groupValues[3].replace(whitespacePattern, ""),
                            u0 = match.groupValues[4].replace(whitespacePattern, ""),
                            u1 = match.groupValues[5].replace(whitespacePattern, "").ifEmpty { null },
                            Q0x = match.groupValues[6].replace(whitespacePattern, ""),
                            Q0y = match.groupValues[if (match.groupValues[7].isEmpty()) 9 else 7].replace(
                                whitespacePattern,
                                ""
                            ),
                            Q1x = match.groupValues[8].replace(whitespacePattern, "").ifEmpty { null },
                            Q1y = if (match.groupValues[7].isEmpty()) null else match.groupValues[9].replace(
                                whitespacePattern,
                                ""
                            ).ifEmpty { null })
            }
            withDataSuites(
                nameFn = {
                    "Input: \"${
                        it.msg.substring(
                            0,
                            min(it.msg.length, 10)
                        )
                    }${if (it.msg.length > 10) "…" else ""}\""
                },
                testcasePattern.findAll(suiteInfo.tests).map(::TestInfo)
            )
            { test ->
                test("hash_to_curve") {
                    val result = suite(test.msg.encodeToByteArray()).normalize()
                    result.curve shouldBe suiteInfo.curve
                    result.x.toString(16).padStart(test.Px.length, '0') shouldBe test.Px
                    result.y.toString(16).padStart(test.Py.length, '0') shouldBe test.Py
                }
               test("hash_to_field") {
                    val htfA = RFC9380.hash_to_field(
                        RFC9380.expand_message_xmd(suiteInfo.curve.nativeDigest), suiteInfo.curve, suiteInfo.dstB
                    )
                    if (test.u1 != null) {
                        val u = htfA(test.msg.encodeToByteArray(), 2)
                        u[0].toString(16).padStart(test.u0.length, '0') shouldBe test.u0
                        u[1].toString(16).padStart(test.u1.length, '0') shouldBe test.u1
                    } else {
                        val u = htfA(test.msg.encodeToByteArray())
                        u.toString(16).padStart(test.u0.length, '0') shouldBe test.u0
                    }
                }
                test("map_to_curve"){
                    val mtc = RFC9380.map_to_curve_simple_swu(suiteInfo.curve)
                    val u0 = BigInteger.parseString(test.u0, 16).toModularBigInteger(suiteInfo.curve.modulus)
                    val Q0 = mtc(u0).normalize()
                    Q0.x.toString(16).padStart(test.Q0x.length, '0') shouldBe test.Q0x
                    Q0.y.toString(16).padStart(test.Q0y.length, '0') shouldBe test.Q0y
                    if (test.u1 != null) {
                        test.Q1x.shouldNotBeNull(); test.Q1y.shouldNotBeNull()
                        val u1 = BigInteger.parseString(test.u1, 16).toModularBigInteger(suiteInfo.curve.modulus)
                        val Q1 = mtc(u1).normalize()
                        Q1.x.toString(16).padStart(test.Q1x.length, '0') shouldBe test.Q1x
                        Q1.y.toString(16).padStart(test.Q1y.length, '0') shouldBe test.Q1y
                    }
                }
            }
        }
    }
    "HashToScalar" - {
        withData(ECCurve.entries) { curve ->
            val hash_to_scalar = curve.hashToScalar(Random.azString(32).encodeToByteArray())
            checkAll(iterations = 5000, Arb.byteArray(Arb.int(25, 125), Arb.byte())) { input ->
                val base = hash_to_scalar(input)
                base.modulus shouldBe curve.order
                val splitPos = Random.nextInt(1, input.size - 2)
                hash_to_scalar(
                    sequenceOf(
                        input.copyOfRange(0, splitPos),
                        input.copyOfRange(splitPos, input.size)
                    )
                ) shouldBe base
                hash_to_scalar(
                    listOf(
                        input.copyOfRange(0, splitPos),
                        input.copyOfRange(splitPos, input.size)
                    )
                ) shouldBe base
            }
        }
    }
}
