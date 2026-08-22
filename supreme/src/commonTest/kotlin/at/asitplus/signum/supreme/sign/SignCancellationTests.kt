package at.asitplus.signum.supreme.sign

import at.asitplus.signum.supreme.isSuccess
import at.asitplus.signum.supreme.signature
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeout
import kotlin.random.Random

val SignCancellationTests by matrixSuite {

    "sign completes normally without cancellation" {
        val signer = Signer.Ephemeral {}.getOrThrow()
        val data = Random.Default.nextBytes(64)
        val result = signer.sign(data)
        result.isSuccess shouldBe true
    }

    "sign respects coroutine cancellation" {
        val signer = Signer.Ephemeral {}.getOrThrow()
        val data = Random.Default.nextBytes(64)
        shouldThrow<CancellationException> {
            coroutineScope {
                cancel()
                signer.sign(data)
            }
        }
    }

    "sign works within withTimeout" {
        val signer = Signer.Ephemeral {}.getOrThrow()
        val data = Random.Default.nextBytes(64)
        val result = withTimeout(5000) {
            signer.sign(data)
        }
        result.isSuccess shouldBe true
    }

    "sign propagates CancellationException instead of wrapping it" {
        val signer = Signer.Ephemeral {}.getOrThrow()
        val data = Random.Default.nextBytes(64)
        val parentJob = Job()
        parentJob.cancel()
        shouldThrow<CancellationException> {
            kotlinx.coroutines.withContext(parentJob) {
                signer.sign(data)
            }
        }
    }
}
