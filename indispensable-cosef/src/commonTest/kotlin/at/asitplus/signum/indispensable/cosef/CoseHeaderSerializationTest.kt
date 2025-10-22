package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromHexString
import kotlinx.serialization.encodeToHexString
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

@OptIn(ExperimentalSerializationApi::class)
val CoseHeaderSerializationTest by testSuite {

    "COSE header with one certificate" {
        val input = """
        a1                                     #         map(1)
           18 21                               #           unsigned(33)
           59 01b7                             #           bytes(439)
              308201b330820158a003020102021475 #             "0\x82\x01\xb30\x82\x01X\xa0\x03\x02\x01\x02\x02\x14u"
              52715f6add323d4934a1ba175dc94575 #             "Rq_j\xdd2=I4\xa1\xba\x17]\xc9Eu"
              5d8b50300a06082a8648ce3d04030230 #             "]\x8bP0\n\x06\x08*\x86H\xce=\x04\x03\x020"
              163114301206035504030c0b72656164 #             "\x161\x140\x12\x06\x03U\x04\x03\x0c\x0bread"
              657220726f6f74301e170d3230313030 #             "er root0\x1e\x17\r20100"
              313030303030305a170d323331323331 #             "1000000Z\x17\r231231"
              3030303030305a3011310f300d060355 #             "000000Z0\x111\x0f0\r\x06\x03U"
              04030c06726561646572305930130607 #             "\x04\x03\x0c\x06reader0Y0\x13\x06\x07"
              2a8648ce3d020106082a8648ce3d0301 #             "*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01"
              0703420004f8912ee0f912b6be683ba2 #             "\x07\x03B\x00\x04\xf8\x91.\xe0\xf9\x12\xb6\xbeh;\xa2"
              fa0121b2630e601b2b628dff3b44f639 #             "\xfa\x01!\xb2c\x0e`\x1b+b\x8d\xff;D\xf69"
              4eaa9abdbcc2149d29d6ff1a3e091135 #             "N\xaa\x9a\xbd\xbc\xc2\x14\x9d)\xd6\xff\x1a>\t\x115"
              177e5c3d9c57f3bf839761eed02c64dd #             "\x17~\\=\x9cW\xf3\xbf\x83\x97a\xee\xd0,d\xdd"
              82ae1d3bbfa38188308185301c060355 #             "\x82\xae\x1d;\xbf\xa3\x81\x880\x81\x850\x1c\x06\x03U"
              1d1f041530133011a00fa00d820b6578 #             "\x1d\x1f\x04\x150\x130\x11\xa0\x0f\xa0\r\x82\x0bex"
              616d706c652e636f6d301d0603551d0e #             "ample.com0\x1d\x06\x03U\x1d\x0e"
              04160414f2dfc4acafc5f30b464fada2 #             "\x04\x16\x04\x14\xf2\xdf\xc4\xac\xaf\xc5\xf3\x0bFO\xad\xa2"
              0bfcd533af5e07f5301f0603551d2304 #             "\x0b\xfc\xd53\xaf^\x07\xf50\x1f\x06\x03U\x1d#\x04"
              1830168014cfb7a881baea5f32b6fb91 #             "\x180\x16\x80\x14\xcf\xb7\xa8\x81\xba\xea_2\xb6\xfb\x91"
              cc29590c50dfac416e300e0603551d0f #             "\xcc)Y\x0cP\xdf\xacAn0\x0e\x06\x03U\x1d\x0f"
              0101ff04040302078030150603551d25 #             "\x01\x01\xff\x04\x04\x03\x02\x07\x800\x15\x06\x03U\x1d%"
              0101ff040b3009060728818c5d050106 #             "\x01\x01\xff\x04\x0b0\t\x06\x07(\x81\x8c]\x05\x01\x06"
              300a06082a8648ce3d04030203490030 #             "0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03I\x000"
              46022100fb9ea3b686fd7ea2f0234858 #             "F\x02!\x00\xfb\x9e\xa3\xb6\x86\xfd~\xa2\xf0#HX"
              ff8328b4efef6a1ef71ec4aae4e30720 #             "\xff\x83(\xb4\xef\xefj\x1e\xf7\x1e\xc4\xaa\xe4\xe3\x07 "
              6f9214930221009b94f0d739dfa84cca #             "o\x92\x14\x93\x02!\x00\x9b\x94\xf0\xd79\xdf\xa8L\xca"
              29efed529dd4838acfd8b6bee212dc63 #             ")\xef\xedR\x9d\xd4\x83\x8a\xcf\xd8\xb6\xbe\xe2\x12\xdcc"
              20c46feb839a35                   #             " \xc4o\xeb\x83\x9a5"
        """.trimIndent().split("\n").joinToString("") { it.split("#").first().replace(" ", "") }

        coseCompliantSerializer.decodeFromHexString<CoseHeader>(input).also {
            it.certificateChain.shouldNotBeNull().shouldHaveSize(1)
        }
    }

    "COSE header with two certificates" {
        val input = """
        a1                                               #           map(1)
          18 21                                          #             unsigned(33)
          82                                             #             array(2)
             59 0278                                     #               bytes(632)
                308202743082021ba003020102020102         #                 "0\x82\x02t0\x82\x02\x1b\xa0\x03\x02\x01\x02\x02\x01\x02"
                300a06082a8648ce3d04030230818831         #                 "0\n\x06\x08*\x86H\xce=\x04\x03\x020\x81\x881"
                0b3009060355040613024445310f300d         #                 "\x0b0\t\x06\x03U\x04\x06\x13\x02DE1\x0f0\r"
                06035504070c064265726c696e311d30         #                 "\x06\x03U\x04\x07\x0c\x06Berlin1\x1d0"
                1b060355040a0c1442756e6465736472         #                 "\x1b\x06\x03U\x04\n\x0c\x14Bundesdr"
                75636b6572656920476d62483111300f         #                 "uckerei GmbH1\x110\x0f"
                060355040b0c08542043532049444531         #                 "\x06\x03U\x04\x0b\x0c\x08T CS IDE1"
                36303406035504030c2d535052494e44         #                 "604\x06\x03U\x04\x03\x0c-SPRIND"
                2046756e6b6520455544492057616c6c         #                 " Funke EUDI Wall"
                65742050726f746f7479706520497373         #                 "et Prototype Iss"
                75696e67204341301e170d3234303533         #                 "uing CA0\x1e\x17\r24053"
                313038313331375a170d323530373035         #                 "1081317Z\x17\r250705"
                3038313331375a306c310b3009060355         #                 "081317Z0l1\x0b0\t\x06\x03U"
                040613024445311d301b060355040a0c         #                 "\x04\x06\x13\x02DE1\x1d0\x1b\x06\x03U\x04\n\x0c"
                1442756e646573647275636b65726569         #                 "\x14Bundesdruckerei"
                20476d6248310a3008060355040b0c01         #                 " GmbH1\n0\x08\x06\x03U\x04\x0b\x0c\x01"
                493132303006035504030c2953505249         #                 "I1200\x06\x03U\x04\x03\x0c)SPRI"
                4e442046756e6b652045554449205761         #                 "ND Funke EUDI Wa"
                6c6c65742050726f746f747970652049         #                 "llet Prototype I"
                73737565723059301306072a8648ce3d         #                 "ssuer0Y0\x13\x06\x07*\x86H\xce="
                020106082a8648ce3d03010703420004         #                 "\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\x00\x04"
                38506ae1830a838c397d389fb32b7006         #                 "8Pj\xe1\x83\n\x83\x8c9}8\x9f\xb3+p\x06"
                e25fffb13b56144f5e2366e764b7ab51         #                 "\xe2_\xff\xb1;V\x14O^#f\xe7d\xb7\xabQ"
                1322005d5f20cade45711b181e1cf8af         #                 "\x13\"\x00]_ \xca\xdeEq\x1b\x18\x1e\x1c\xf8\xaf"
                2cfdeeb8cbd2ea20c473ba8cc66bddb8         #                 ",\xfd\xee\xb8\xcb\xd2\xea \xc4s\xba\x8c\xc6k\xdd\xb8"
                a3819030818d301d0603551d0e041604         #                 "\xa3\x81\x900\x81\x8d0\x1d\x06\x03U\x1d\x0e\x04\x16\x04"
                1488f84290b12b0d73cb5b6fc9d1655e         #                 "\x14\x88\xf8B\x90\xb1+\rs\xcb[o\xc9\xd1e^"
                821cb0fa62300c0603551d130101ff04         #                 "\x82\x1c\xb0\xfab0\x0c\x06\x03U\x1d\x13\x01\x01\xff\x04"
                023000300e0603551d0f0101ff040403         #                 "\x020\x000\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03"
                020780302d0603551d11042630248222         #                 "\x02\x07\x800-\x06\x03U\x1d\x11\x04&0${'$'}\x82\""
                64656d6f2e7069642d6973737565722e         #                 "demo.pid-issuer."
                62756e646573647275636b657265692e         #                 "bundesdruckerei."
                6465301f0603551d23041830168014d4         #                 "de0\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14\xd4"
                5618c08938e80e588418c97662bfabbb         #                 "V\x18\xc0\x898\xe8\x0eX\x84\x18\xc9vb\xbf\xab\xbb"
                c590be300a06082a8648ce3d04030203         #                 "\xc5\x90\xbe0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03"
                4700304402201b7f94f391c43385f5a8         #                 "G\x000D\x02 \x1b\x7f\x94\xf3\x91\xc43\x85\xf5\xa8"
                228ca2d5537b77c23d06c14a9b531696         #                 "\"\x8c\xa2\xd5S{w\xc2=\x06\xc1J\x9bS\x16\x96"
                e4698766f219022029891dacd7f6c573         #                 "\xe4i\x87f\xf2\x19\x02 )\x89\x1d\xac\xd7\xf6\xc5s"
                e35526e35bf53fe52e6f0040b95f170e         #                 "\xe3U&\xe3[\xf5?\xe5.o\x00@\xb9_\x17\x0e"
                6a7bac381ae805b5                         #                 "j{\xac8\x1a\xe8\x05\xb5"
             59 027d                                     #               bytes(637)
                3082027930820220a003020102021407         #                 "0\x82\x02y0\x82\x02 \xa0\x03\x02\x01\x02\x02\x14\x07"
                913d41566d99461c0ed0a3281fc7dd54         #                 "\x91=AVm\x99F\x1c\x0e\xd0\xa3(\x1f\xc7\xddT"
                2fef68300a06082a8648ce3d04030230         #                 "/\xefh0\n\x06\x08*\x86H\xce=\x04\x03\x020"
                8188310b300906035504061302444531         #                 "\x81\x881\x0b0\t\x06\x03U\x04\x06\x13\x02DE1"
                0f300d06035504070c064265726c696e         #                 "\x0f0\r\x06\x03U\x04\x07\x0c\x06Berlin"
                311d301b060355040a0c1442756e6465         #                 "1\x1d0\x1b\x06\x03U\x04\n\x0c\x14Bunde"
                73647275636b6572656920476d624831         #                 "sdruckerei GmbH1"
                11300f060355040b0c08542043532049         #                 "\x110\x0f\x06\x03U\x04\x0b\x0c\x08T CS I"
                44453136303406035504030c2d535052         #                 "DE1604\x06\x03U\x04\x03\x0c-SPR"
                494e442046756e6b6520455544492057         #                 "IND Funke EUDI W"
                616c6c65742050726f746f7479706520         #                 "allet Prototype "
                49737375696e67204341301e170d3234         #                 "Issuing CA0\x1e\x17\r24"
                303533313036343830395a170d333430         #                 "0531064809Z\x17\r340"
                3532393036343830395a308188310b30         #                 "529064809Z0\x81\x881\x0b0"
                09060355040613024445310f300d0603         #                 "\t\x06\x03U\x04\x06\x13\x02DE1\x0f0\r\x06\x03"
                5504070c064265726c696e311d301b06         #                 "U\x04\x07\x0c\x06Berlin1\x1d0\x1b\x06"
                0355040a0c1442756e64657364727563         #                 "\x03U\x04\n\x0c\x14Bundesdruc"
                6b6572656920476d62483111300f0603         #                 "kerei GmbH1\x110\x0f\x06\x03"
                55040b0c085420435320494445313630         #                 "U\x04\x0b\x0c\x08T CS IDE160"
                3406035504030c2d535052494e442046         #                 "4\x06\x03U\x04\x03\x0c-SPRIND F"
                756e6b6520455544492057616c6c6574         #                 "unke EUDI Wallet"
                2050726f746f74797065204973737569         #                 " Prototype Issui"
                6e672043413059301306072a8648ce3d         #                 "ng CA0Y0\x13\x06\x07*\x86H\xce="
                020106082a8648ce3d03010703420004         #                 "\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\x00\x04"
                606cddc050e773bf8a9f989b02f08e33         #                 "`l\xdd\xc0P\xe7s\xbf\x8a\x9f\x98\x9b\x02\xf0\x8e3"
                c91eefb550c6a7cc73064bf0868803e5         #                 "\xc9\x1e\xef\xb5P\xc6\xa7\xccs\x06K\xf0\x86\x88\x03\xe5"
                8244e7027e663f8221fddaa32bbb9a7f         #                 "\x82D\xe7\x02~f?\x82!\xfd\xda\xa3+\xbb\x9a\x7f"
                9323a2bc4d110bf21b74c38dbc3a14c9         #                 "\x93#\xa2\xbcM\x11\x0b\xf2\x1bt\xc3\x8d\xbc:\x14\xc9"
                a3663064301d0603551d0e04160414d4         #                 "\xa3f0d0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\xd4"
                5618c08938e80e588418c97662bfabbb         #                 "V\x18\xc0\x898\xe8\x0eX\x84\x18\xc9vb\xbf\xab\xbb"
                c590be301f0603551d23041830168014         #                 "\xc5\x90\xbe0\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14"
                d45618c08938e80e588418c97662bfab         #                 "\xd4V\x18\xc0\x898\xe8\x0eX\x84\x18\xc9vb\xbf\xab"
                bbc590be30120603551d130101ff0408         #                 "\xbb\xc5\x90\xbe0\x12\x06\x03U\x1d\x13\x01\x01\xff\x04\x08"
                30060101ff020100300e0603551d0f01         #                 "0\x06\x01\x01\xff\x02\x01\x000\x0e\x06\x03U\x1d\x0f\x01"
                01ff040403020186300a06082a8648ce         #                 "\x01\xff\x04\x04\x03\x02\x01\x860\n\x06\x08*\x86H\xce"
                3d040302034700304402206126ef0919         #                 "=\x04\x03\x02\x03G\x000D\x02 a&\xef\t\x19"
                287b7f6ad6f831d1675d6eb2ae7c0c51         #                 "({\x7fj\xd6\xf81\xd1g]n\xb2\xae|\x0cQ"
                3daed77ea076d975d18ea102206e4c5a         #                 "=\xae\xd7~\xa0v\xd9u\xd1\x8e\xa1\x02 nLZ"
                af558b61d6b6f1cc23f4c566479902bd         #                 "\xafU\x8ba\xd6\xb6\xf1\xcc#\xf4\xc5fG\x99\x02\xbd"
                915cb19fc18f7d7dbb108cf3b3               #                 "\x91\\\xb1\x9f\xc1\x8f}}\xbb\x10\x8c\xf3\xb3"
        """.trimIndent().split("\n").joinToString("") { it.split("#").first().replace(" ", "") }

        coseCompliantSerializer.decodeFromHexString<CoseHeader>(input).also {
            it.certificateChain.shouldNotBeNull().shouldHaveSize(2)
        }
    }

}