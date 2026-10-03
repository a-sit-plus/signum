package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.sign.SignatureResult
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.sign.sign
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds

val SignCancellationTests by matrixSuite {
    "sign succeeds normally" {
        val signer = Signer.Ephemeral {}
        val data = Random.Default.nextBytes(64)
        val result = signer.sign(data)
        (result is SignatureResult.Success<*>) shouldBe true
    }

    "sign respects coroutine cancellation" {
        val signer = Signer.Ephemeral {}
        val data = Random.Default.nextBytes(64)
        shouldThrow<CancellationException> {
            coroutineScope {
                cancel()
                signer.sign(data)
            }
        }
    }

    "sign works within withTimeout" {
        val signer = Signer.Ephemeral {}
        val data = Random.Default.nextBytes(64)
        val result = withTimeout(5.seconds) {
            signer.sign(data)
        }
        (result is SignatureResult.Success<*>) shouldBe true
    }

    "sign propagates CancellationException instead of wrapping it" {
        val signer = Signer.Ephemeral {}
        val data = Random.Default.nextBytes(64)
        val parentJob = Job()
        parentJob.cancel()
        shouldThrow<CancellationException> {
            withContext(parentJob) {
                signer.sign(data)
            }
        }
    }
}
