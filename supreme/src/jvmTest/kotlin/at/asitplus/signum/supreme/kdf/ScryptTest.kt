package at.asitplus.signum.supreme.kdf

import at.asitplus.signum.indispensable.misc.bytes
import at.asitplus.signum.internals.ByteArrayView
import at.asitplus.signum.internals.toLEByteArray
import at.asitplus.signum.internals.toUIntArrayLE
import at.asitplus.signum.internals.view
import at.asitplus.signum.supreme.b
import com.lambdaworks.crypto.SCrypt
import io.kotest.assertions.withClue
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import at.asitplus.testballoon.checkAllTests
import at.asitplus.testballoon.checkAllSuites
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.Exhaustive
import io.kotest.property.arbitrary.*
import io.kotest.property.exhaustive.ints
import kotlin.math.pow
import at.asitplus.signum.indispensable.kdf.SCrypt as scrypt
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

private val rnd = java.util.Random()

@OptIn(ExperimentalStdlibApi::class)
val ScryptTest  by testSuite() {
    "Little-Endian Bytearray converters" {
        ByteArray(8).also {
            uintArrayOf(0x31b2a3f4u, 0x72ff9813u).toLEByteArray(it.view)
        } shouldBe ubyteArrayOf(0xf4u, 0xa3u, 0xb2u, 0x31u, 0x13u, 0x98u, 0xffu, 0x72u).asByteArray()

        UIntArray(2).also {
            ubyteArrayOf(0x28u, 0xf3u, 0x79u, 0xc2u, 0x97u, 0xffu, 0xfbu, 0xfeu).asByteArray().view.toUIntArrayLE(it)
        } shouldBe uintArrayOf(0xc279f328u, 0xfefbff97u)
    }
    "Integerify" - {
        checkAllSuites(Exhaustive.ints(1..30)) { Npow ->
            val N = 1 shl Npow
            val r = 8
            checkAllTests(iterations = 64, Arb.byteArray(Arb.constant(128 * r), Arb.byte())) { input ->
                withClue("input=${input.toHexString(HexFormat.UpperCase).let { it.substring(it.length - 128) }}") {
                    scrypt(
                        cost = N,
                        blockSize = r,
                        parallelization = 1
                    ).integerify(input.view) shouldBe SCrypt.integerify(input, 0, r).mod(N)
                }
            }
        }
    }
    "Salsa20/8 Core" {
        // FROM RFC 7914
        val input = b(
            " 7e 87 9a 21 4f 3e c9 86 7c a9 40 e6 41 71 8f 26\n" +
                    "   ba ee 55 5b 8c 61 c1 b5 0d f8 46 11 6d cd 3b 1d\n" +
                    "   ee 24 f3 19 df 9b 3d 85 14 12 1e 4b 5a c5 aa 32\n" +
                    "   76 02 1d 29 09 c7 48 29 ed eb c6 8d b8 b8 c2 5e\n"
        )

        val output = b(
            "a4 1f 85 9c 66 08 cc 99 3b 81 ca cb 02 0c ef 05\n" +
                    "   04 4b 21 81 a2 fd 33 7d fd 7b 1c 63 96 68 2f 29\n" +
                    "   b4 39 31 68 e3 c9 e6 bc fe 6b c5 b7 a0 6d 96 ba\n" +
                    "   e4 24 cc 10 2c 91 74 5c 24 ad 67 3d c7 61 8f 81"
        )
        input.also {
            scrypt(cost = 2, blockSize = 1, parallelization = 1).Mixer().`salsa20_8core`(it.view)
        } shouldBe output
    }
    "scryptBlockMix" {
        val input = b(
            "f7 ce 0b 65 3d 2d 72 a4 10 8c f5 ab e9 12 ff dd\n" +
                    "           77 76 16 db bb 27 a7 0e 82 04 f3 ae 2d 0f 6f ad\n" +
                    "           89 f6 8f 48 11 d1 e8 7b cc 3b d7 40 0a 9f fd 29\n" +
                    "           09 4f 01 84 63 95 74 f3 9a e5 a1 31 52 17 bc d7\n" +
                    "           89 49 91 44 72 13 bb 22 6c 25 b5 4d a8 63 70 fb\n" +
                    "           cd 98 43 80 37 46 66 bb 8f fc b5 bf 40 c2 54 b0\n" +
                    "           67 d2 7c 51 ce 4a d5 fe d8 29 c9 0b 50 5a 57 1b\n" +
                    "           7f 4d 1c ad 6a 52 3c da 77 0e 67 bc ea af 7e 89"
        )
        val output = b(
            "a4 1f 85 9c 66 08 cc 99 3b 81 ca cb 02 0c ef 05\n" +
                    "           04 4b 21 81 a2 fd 33 7d fd 7b 1c 63 96 68 2f 29\n" +
                    "           b4 39 31 68 e3 c9 e6 bc fe 6b c5 b7 a0 6d 96 ba\n" +
                    "           e4 24 cc 10 2c 91 74 5c 24 ad 67 3d c7 61 8f 81\n" +
                    "           20 ed c9 75 32 38 81 a8 05 40 f6 4c 16 2d cd 3c\n" +
                    "           21 07 7c fe 5f 8d 5f e2 b1 a4 16 8f 95 36 78 b7\n" +
                    "           7d 3b 3d 80 3b 60 e4 ab 92 09 96 e5 9b 4d 53 b6\n" +
                    "           5d 2a 22 58 77 d5 ed f5 84 2c b9 f1 4e ef e4 25"
        )
        input.also {
            scrypt(cost = 2, blockSize = 1, parallelization = 1).Mixer().scryptBlockMix(it.view)
        } shouldBe output
    }
    "scryptROMix" - {
        "Fixed Test Vector (RFC7914)" {
            val input = b(
                "f7 ce 0b 65 3d 2d 72 a4 10 8c f5 ab e9 12 ff dd\n" +
                        "       77 76 16 db bb 27 a7 0e 82 04 f3 ae 2d 0f 6f ad\n" +
                        "       89 f6 8f 48 11 d1 e8 7b cc 3b d7 40 0a 9f fd 29\n" +
                        "       09 4f 01 84 63 95 74 f3 9a e5 a1 31 52 17 bc d7\n" +
                        "       89 49 91 44 72 13 bb 22 6c 25 b5 4d a8 63 70 fb\n" +
                        "       cd 98 43 80 37 46 66 bb 8f fc b5 bf 40 c2 54 b0\n" +
                        "       67 d2 7c 51 ce 4a d5 fe d8 29 c9 0b 50 5a 57 1b\n" +
                        "       7f 4d 1c ad 6a 52 3c da 77 0e 67 bc ea af 7e 89"
            )
            val output = b(
                "79 cc c1 93 62 9d eb ca 04 7f 0b 70 60 4b f6 b6\n" +
                        "       2c e3 dd 4a 96 26 e3 55 fa fc 61 98 e6 ea 2b 46\n" +
                        "       d5 84 13 67 3b 99 b0 29 d6 65 c3 57 60 1f b4 26\n" +
                        "       a0 b2 f4 bb a2 00 ee 9f 0a 43 d1 9b 57 1a 9c 71\n" +
                        "       ef 11 42 e6 5d 5a 26 6f dd ca 83 2c e5 9f aa 7c\n" +
                        "       ac 0b 9c f1 be 2b ff ca 30 0d 01 ee 38 76 19 c4\n" +
                        "       ae 12 fd 44 38 f2 03 a0 e4 e1 c4 7e c3 14 86 1f\n" +
                        "       4e 90 87 cb 33 39 6a 68 73 e8 f9 d2 53 9a 4b 8e\n"
            )
            input.copyOf().also {
                scrypt(cost = 16, blockSize = 1, parallelization = 1).Mixer().scryptROMix(it.view)
            } shouldBe output
        }
        "Random Test Vectors" {

            val N = 512
            val r = 8
            val scryptInstance = scrypt(N, blockSize = r, parallelization = 1)


            with(scryptInstance.Mixer()) {
                val input = ByteArray(128 * r) {0}.apply { rnd.nextBytes(this) }
                val output = input.copyOf().also {
                    scryptROMix(ByteArrayView(it, 0, it.size))
                }
                output shouldBe input.copyOf().also {
                    SCrypt.smix(it, 0, r, N, ByteArray(128 * r * N), ByteArray(256 * r))
                }

            }
        }
    }

    "Against JVM reference" - {
        checkAllSuites(iterations = 3, Arb.nonNegativeInt(6)) {
            val p = 2.0.pow(it + 1).toInt()
            checkAllSuites(iterations = 3, Arb.nonNegativeInt(7)) {
                val N = 2.0.pow(it+1).toInt()
                checkAllSuites(iterations = 4, Arb.nonNegativeInt(4)) {
                    val r = it + 1
                    val scryptInstance = scrypt(N, blockSize = r, parallelization = p)
                    checkAllSuites(iterations = 6, Arb.byteArray(Arb.positiveInt(16), Arb.byte())) { salt ->
                        checkAllSuites(iterations = 6, Arb.byteArray(Arb.positiveInt(32), Arb.byte())) { ikm ->
                            checkAllTests(iterations = 6, Arb.nonNegativeInt(256)) { len ->
                                SCrypt.scrypt(ikm, salt, N, r, p, len) shouldBe scryptInstance.deriveKey(
                                    salt,
                                    ikm,
                                    len.bytes
                                ).getOrThrow()
                            }
                        }
                    }
                }
            }
        }
    }
}