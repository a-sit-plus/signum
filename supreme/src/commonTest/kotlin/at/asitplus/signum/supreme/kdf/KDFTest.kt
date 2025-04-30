package at.asitplus.signum.supreme.kdf

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.HMAC
import at.asitplus.signum.indispensable.kdf.HKDF
import at.asitplus.signum.indispensable.kdf.PBKDF2
import at.asitplus.signum.indispensable.misc.bytes
import at.asitplus.signum.supreme.a
import at.asitplus.signum.supreme.b
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import com.ionspin.kotlin.bignum.integer.Quadruple

class KDFTest : FreeSpec({
    "HKDF" - {
        "Fixed Text Vectors" - {
            class TestInfo(val Comment: String, val Hash: Digest, IKM: String, salt: String?,
                           info: String, val L: Int, PRK: String, OKM: String) {
                val IKM = b(IKM); val salt = salt?.let(::b); val info = b(info); val PRK = b(PRK); val OKM = b(OKM)
                init { check(L == this.OKM.size) }
            }
            withData(nameFn=TestInfo::Comment, sequence {
                yield(TestInfo("Basic test case with SHA-256",
                    Hash=Digest.SHA256,
                    IKM="0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                    salt="000102030405060708090a0b0c",
                    info="f0f1f2f3f4f5f6f7f8f9",
                    L=42,
                    PRK="077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                    OKM="3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))
                yield(TestInfo("Test with SHA-256 and longer inputs/outputs",
                    Hash=Digest.SHA256,
                    IKM="000102030405060708090a0b0c0d0e0f\n" +
                            "          101112131415161718191a1b1c1d1e1f\n" +
                            "          202122232425262728292a2b2c2d2e2f\n" +
                            "          303132333435363738393a3b3c3d3e3f\n" +
                            "          404142434445464748494a4b4c4d4e4f",
                    salt="0x606162636465666768696a6b6c6d6e6f\n" +
                            "          707172737475767778797a7b7c7d7e7f\n" +
                            "          808182838485868788898a8b8c8d8e8f\n" +
                            "          909192939495969798999a9b9c9d9e9f\n" +
                            "          a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                    info="0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\n" +
                            "          c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\n" +
                            "          d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\n" +
                            "          e0e1e2e3e4e5e6e7e8e9eaebecedeeef\n" +
                            "          f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                    L=82,
                    PRK="06a6b88c5853361a06104c9ceb35b45c\n" +
                            "          ef760014904671014a193f40c15fc244",
                    OKM="b11e398dc80327a1c8e7f78c596a4934\n" +
                            "          4f012eda2d4efad8a050cc4c19afa97c\n" +
                            "          59045a99cac7827271cb41c65e590e09\n" +
                            "          da3275600c2f09b8367793a9aca3db71\n" +
                            "          cc30c58179ec3e87c14c01d5c1f3434f\n" +
                            "          1d87"))
                yield(TestInfo("Test with SHA-256 and zero-length salt/info",
                    Hash=Digest.SHA256,
                    IKM="0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                    salt="",
                    info="",
                    L=42,
                    PRK="19ef24a32c717b167f33a91d6f648bdf\n" +
                            "          96596776afdb6377ac434c1c293ccb04",
                    OKM="8da4e775a563c18f715f802a063c5a31\n" +
                            "          b8a11f5c5ee1879ec3454e5f3c738d2d\n" +
                            "          9d201395faa4b61a96c8"))
                yield(TestInfo("Basic test case with SHA-1",
                    Hash=Digest.SHA1,
                    IKM="0b0b0b0b0b0b0b0b0b0b0b",
                    salt="000102030405060708090a0b0c",
                    info="f0f1f2f3f4f5f6f7f8f9",
                    L=42,
                    PRK="9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
                    OKM="085a01ea1b10f36933068b56efa5ad81\n" +
                            "          a4f14b822f5b091568a9cdd4f155fda2\n" +
                            "          c22e422478d305f3f896"))
                yield(TestInfo("Test with SHA-1 and zero-length salt/info",
                    Hash=Digest.SHA1,
                    IKM="0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                    salt="",
                    info="",
                    L=42,
                    PRK="da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
                    OKM="0ac1af7002b3d761d1e55298da9d0506\n" +
                            "          b9ae52057220a306e07b6b87e8df21d0\n" +
                            "          ea00033de03984d34918"))
                yield(TestInfo("Test with SHA-1, salt not provided (defaults to HashLen zero octets),\n" +
                        "   zero-length info",
                    Hash=Digest.SHA1,
                    IKM="0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
                    salt=null,
                    info="",
                    L=42,
                    PRK="2adccada18779e7c2077ad2eb19d3f3e731385dd",
                    OKM="2c91117204d745f3500d636a62f64f0a\n" +
                            "          b3bae548aa53d423b0d1f27ebba6f5e5\n" +
                            "          673a081d70cce7acfc48"))
            }) { t ->
                val hkdf = HKDF(t.Hash)
                val prk = hkdf.extract(t.salt, t.IKM).getOrThrow()
                prk shouldBe t.PRK
                val okm = hkdf.expand(prk, t.info, t.L).getOrThrow()
                okm shouldBe t.OKM
            }
        }
    }
    "RFC2898 PBKDF2" - {
        "PBKDF2-HMAC-SHA-1" - {
            withData(nameFn={ "RFC6070: \"${it.d}\""}, sequence {
                yield(Quadruple("password", "salt", 1, "" +
                        "0c 60 c8 0f 96 1f 0e 71\n" +
                        "            f3 a9 b5 24 af 60 12 06\n" +
                        "            2f e0 37 a6"))
                yield(Quadruple("password", "salt", 2, "" +
                        "ea 6c 01 4d c7 2d 6f 8c\n" +
                        "            cd 1e d9 2a ce 1d 41 f0\n" +
                        "            d8 de 89 57"))
                yield(Quadruple("password", "salt", 4096, "" +
                        "4b 00 79 01 b7 65 48 9a\n" +
                        "            be ad 49 d9 26 f7 21 d0\n" +
                        "            65 a4 29 c1"))
                yield(Quadruple("password", "salt", 16777216, "" +
                        "ee fe 3d 61 cd 4d a4 e4\n" +
                        "            e9 94 5b 3d 6b a2 15 8c\n" +
                        "            26 34 e9 84"))
                yield(Quadruple("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, "" +
                        "3d 2e ec 4f e4 1c 84 9b\n" +
                        "            80 c8 d8 36 62 c0 e4 4a\n" +
                        "            8b 29 1a 96 4c f2 f0 70\n" +
                        "            38"))
                yield(Quadruple("pass\u0000word", "sa\u0000lt", 4096, "" +
                        "56 fa 6a a7 55 48 09 9d\n" +
                        "            cc 37 d7 f0 34 25 e0 c3"))
            }) { (P, S, c, ref) ->
                PBKDF2(HMAC.SHA1,c).deriveKey(ikm=a(P),salt=a(S),dkLength=b(ref).size.bytes).getOrThrow() shouldBe b(ref)
            }
        }
        "PBKDF2-HMAC-SHA-256" - {
            "RFC7914: passwd" {
                PBKDF2(HMAC.SHA256, 1).deriveKey(ikm=a("passwd"), salt=a("salt"), dkLength=64.bytes).getOrThrow() shouldBe
                        b("55 ac 04 6e 56 e3 08 9f ec 16 91 c2 25 44 b6 05\n" +
                                "   f9 41 85 21 6d de 04 65 e6 8b 9d 57 c2 0d ac bc\n" +
                                "   49 ca 9c cc f1 79 b6 45 99 16 64 b3 9d 77 ef 31\n" +
                                "   7c 71 b8 45 b1 e3 0b d5 09 11 20 41 d3 a1 97 83")
            }
            "RFC7914: Password" {
                PBKDF2(HMAC.SHA256,iterations=80000).deriveKey(ikm=a("Password"), salt=a("NaCl"), dkLength=64.bytes).getOrThrow() shouldBe
                        b("4d dc d8 f6 0b 98 be 21 83 0c ee 5e f2 27 01 f9\n" +
                                "   64 1a 44 18 d0 4c 04 14 ae ff 08 87 6b 34 ab 56\n" +
                                "   a1 d4 25 a1 22 58 33 54 9a db 84 1b 51 c9 b3 17\n" +
                                "   6a 27 2b de bb a1 d0 78 47 8f 62 b3 97 f3 3c 8d")
            }
        }
    }
})
