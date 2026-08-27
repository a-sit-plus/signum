package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.integrity.SignatureInput
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.sequences.shouldContainExactly
import io.kotest.matchers.shouldBe
import kotlin.random.Random

val SignatureInputTest by matrixSuite {
    "SignatureInput creation" {
        val bytes = Random.nextBytes(64)
        val input = SignatureInput(bytes)
        input.data.single() shouldBe bytes
        input.format shouldBe null
    }
    "SignatureInput creation (unsafe)" {
        val bytes = Random.nextBytes(64)
        shouldThrowAny { SignatureInput.unsafeCreate(bytes, Digest.SHA256) }
        val input = SignatureInput.unsafeCreate(bytes, Digest.SHA512)
        input.data.single() shouldBe bytes
        input.format shouldBe Digest.SHA512
    }
    "SignatureInput collapsing (single-part)" {
        val bytes = Random.nextBytes(256)
        val input = SignatureInput(sequenceOf(bytes).constrainOnce())
        val collapsed = input.collapsed()
        collapsed.format shouldBe null
        collapsed.data.single() shouldBe bytes
    }
    "SignatureInput collapsing (multi-part)" {
        val bytes = Random.nextBytes(256)
        val part1 = bytes.copyOfRange(0, 32)
        val part2 = bytes.copyOfRange(32, 96)
        val part3 = bytes.copyOfRange(96, 256)
        val input = SignatureInput(sequenceOf(part1, part2, part3))
        input.format shouldBe null
        input.data shouldContainExactly sequenceOf(part1, part2, part3)
        val collapsed = input.collapsed()
        collapsed.format shouldBe null
        collapsed.data.single() shouldBe bytes
    }
}
