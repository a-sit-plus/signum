package io.kotest.property

import de.infix.testBalloon.framework.TestInvocation
import de.infix.testBalloon.framework.TestSession
import de.infix.testBalloon.framework.invocation

//Supercharge tests with concurrency!
class ModuleTestSession : TestSession(testConfig = DefaultConfiguration.invocation(TestInvocation.CONCURRENT))