package io.kotest.property

import de.infix.testBalloon.framework.TestInvocation
import de.infix.testBalloon.framework.TestSession
import de.infix.testBalloon.framework.invocation
import de.infix.testBalloon.framework.testScope
import kotlin.time.Duration.Companion.minutes

//Don't supercharge tests with concurrency, a it messes with some stateful tests!
class ModuleTestSession : TestSession(
    testConfig = DefaultConfiguration.testScope(isEnabled = true, timeout = 20.minutes)
)