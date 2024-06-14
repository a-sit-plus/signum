package at.asitplus.crypto.provider

import at.asitplus.KmmResult
import io.kotest.matchers.Matcher
import io.kotest.matchers.MatcherResult

internal object succeed: Matcher<KmmResult<*>> {
    override fun test(value: KmmResult<*>) =
        MatcherResult(value.isSuccess,
            failureMessageFn = { "Should have succeeded, but failed:\n${value.exceptionOrNull()!!.stackTraceToString()}"},
            negatedFailureMessageFn = { "Should have failed, but succeeded with ${value.getOrNull()!!}"})
}
