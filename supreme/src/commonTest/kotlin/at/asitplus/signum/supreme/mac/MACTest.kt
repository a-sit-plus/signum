
package at.asitplus.signum.supreme.mac

import at.asitplus.signum.indispensable.HMAC
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.supreme.b
import at.asitplus.test.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe

class MACTest : FreeSpec({
    "RFC4231" - {
        class I(val comment: String, key: String, data: String,
                SHA224: String, SHA256: String, SHA384: String, SHA512: String) {
            val k = b(key); val d = b(data); val ref224 = b(SHA224);
            val ref256 = b(SHA256); val ref384 = b(SHA384); val ref512 = b(SHA512)
        }
        withData(nameFn=I::comment, sequence {
            yield(I("<base case>",
                key="0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                data="4869205468657265",
                SHA224="896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
                SHA256="b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                SHA384="afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cf" +
                        "aea9ea9076ede7f4af152e8b2fa9cb6",
                SHA512="87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545" +
                        "e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"))
            yield(I("Test with a key shorter than the length of the HMAC output.",
                key="4a656665",
                data="7768617420646f2079612077616e7420666f72206e6f7468696e673f",
                SHA224="a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
                SHA256="5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                SHA384="af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8" +
                        "e2240ca5e69e2c78b3239ecfab21649",
                SHA512="164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554" +
                        "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"))
            yield(I("Test with a combined length of key and data that is larger than 64 " +
                    "bytes (= block-size of SHA-224 and SHA-256).",
                key="a".repeat(40),
                data="d".repeat(100),
                SHA224="7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
                SHA256="773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
                SHA384="88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b" +
                        "2a5ab39dc13814b94e3ab6e101a34f27",
                SHA512="fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39" +
                        "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"))
            yield(I("Test with a combined length of key and data that is larger than 64 " +
                    "bytes (= block-size of SHA-224 and SHA-256). (#2)",
                key="0102030405060708090a0b0c0d0e0f10111213141516171819",
                data="cd".repeat(50),
                SHA224="6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
                SHA256="82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
                SHA384="3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e" +
                        "6801dd23c4a7d679ccf8a386c674cffb",
                SHA512="b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db" +
                        "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"))
            yield(I("Test with a key larger than 128 bytes (= block-size of SHA-384 and SHA-512).",
                key="a".repeat(262),
                data="54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65" +
                        "204b6579202d2048617368204b6579204669727374",
                SHA224="95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
                SHA256="60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                SHA384="4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6" +
                        "0c2ef6ab4030fe8296248df163f44952",
                SHA512="80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352" +
                        "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"))
            yield(I("Test with a key and data that is larger than 128 bytes " +
                    "(= block-size of SHA-384 and SHA-512).",
                key="a".repeat(262),
                data="5468697320697320612074657374207573696e672061206c6172676572207468" +
                        "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074" +
                        "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565" +
                        "647320746f20626520686173686564206265666f7265206265696e6720757365" +
                        "642062792074686520484d414320616c676f726974686d2e",
                SHA224="3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
                SHA256="9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
                SHA384="6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5" +
                        "a678cc31e799176d3860e6110c46523e",
                SHA512="e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944" +
                        "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"))
        }) { info ->
            check(info.ref224.size == 28)
            check(info.ref256.size == 32)
            check(info.ref384.size == 48)
            check(info.ref512.size == 64)

            HMAC.SHA256.mac(key=info.k, msg=info.d).getOrThrow() shouldBe info.ref256
            HMAC.SHA384.mac(key=info.k, msg=info.d).getOrThrow() shouldBe info.ref384
            HMAC.SHA512.mac(key=info.k, msg=info.d).getOrThrow() shouldBe info.ref512
        }
    }
    "Truncated" {
        HMAC.SHA256.truncatedTo(3.bit)
            .mac(key=b("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), b("4869205468657265"))
            .getOrThrow() shouldBe byteArrayOf(0xa0.toByte())
    }
})
