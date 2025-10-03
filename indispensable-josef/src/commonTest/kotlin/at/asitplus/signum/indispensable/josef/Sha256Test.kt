//adapted from this public domain code: https://github.com/asyncant/sha256-kt/blob/master/src/commonTest/kotlin/com/asyncant/crypto/sha256JvmTest.kt
package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.sha256
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope


/** Origin: https://www.di-mgt.com.au/sha_testvectors.html */
val Sha256Test by testSuite(testConfig = TestConfig.testScope(isEnabled = true, timeout = 20.minutes)) {

    "Testvectors" {
        val emptyStringHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        byteArrayOf().sha256().toHexString() shouldBe emptyStringHash

        val abcHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        "abc".encodeToByteArray().sha256().toHexString() shouldBe abcHash

        val abc448BitsHash = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".encodeToByteArray().sha256().toHexString() shouldBe
                abc448BitsHash


        val abc896BitsHash = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        val abc896Bits =
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqr" +
                    "smnopqrstnopqrstu"

        abc896BitsHash shouldBe
                abc896Bits.encodeToByteArray().sha256().toHexString()
        val aOneMillionHash = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        "a".repeat(1000000).encodeToByteArray().sha256().toHexString() shouldBe aOneMillionHash

    }
}

internal fun ByteArray.toHexString() = fold("") { str, it -> str + (0xFF and it.toInt()).toString(16).padStart(2, '0') }
