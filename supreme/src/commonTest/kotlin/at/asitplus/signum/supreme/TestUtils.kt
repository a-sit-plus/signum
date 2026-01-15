@file:OptIn(ExperimentalStdlibApi::class)

package at.asitplus.signum.supreme

import at.asitplus.KmmResult
import io.kotest.matchers.Matcher
import io.kotest.matchers.MatcherResult
import io.kotest.property.Arb
import io.kotest.property.RandomSource
import io.kotest.property.arbitrary.Codepoint
import io.kotest.property.arbitrary.az
import io.kotest.property.arbitrary.string
import org.kotlincrypto.random.CryptoRand
import kotlin.random.Random


fun Random.azString(length: Int): String {
    return Arb.string(minSize = length, maxSize = length, Codepoint.az()).sample(
        RandomSource(this,nextLong())
    ).value
}
internal object succeed: Matcher<KmmResult<*>> {
    override fun test(value: KmmResult<*>) =
        MatcherResult(value.isSuccess,
            failureMessageFn = { "Should have succeeded, but failed:\n${value.exceptionOrNull()!!.stackTraceToString()}"},
            negatedFailureMessageFn = { "Should have failed, but succeeded with ${value.getOrNull()!!}"})
}


/** String -> UTF-8 bytes */ fun a(s: String) = s.encodeToByteArray()
/** Hex String -> bytes */   fun b(s: String) = s.replace("(^0x)|([^0-9a-fA-F])".toRegex(), "").hexToByteArray()
/** Decimal String -> Int */ fun i(s: String) = s.toInt(10)
fun unreachable(): Nothing = throw IllegalStateException()


object InsecureRandom: CryptoRand() {
    override fun nextBytes(buf: ByteArray) = Random.nextBytes(buf)
    fun nextBytes(size: Int) = Random.nextBytes(size)
}