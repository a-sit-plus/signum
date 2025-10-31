package at.asitplus.signum.indispensable

import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.test.enumConsistencyTest
import de.infix.testBalloon.framework.TestDiscoverable
import de.infix.testBalloon.framework.testSuite
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.reflect.KClass
import kotlin.reflect.full.companionObject

val EnumEntriesTest by testSuite {
    enumConsistencyTest("IndispensableEnums")
}