package at.asitplus.signum.indispensable.asn1

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.TestInvocation
import de.infix.testBalloon.framework.invocation
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

val KnownOIDTests by testSuite {

    val dateDescription = KnownOIDs.date
    "Before Adding known OIDs" {
        KnownOIDs[dateDescription].shouldBeNull()
    }

    "After adding known descriptions" {
        KnownOIDs.describeAll()
        KnownOIDs[dateDescription].shouldNotBeNull()
    }

    "Own descriptions" {

        @OptIn(ExperimentalUuidApi::class)
        val expressionistOID= ObjectIdentifier(Uuid.random())

        KnownOIDs[expressionistOID].shouldBeNull()
        KnownOIDs[expressionistOID] = "Edvard Munch"
        KnownOIDs[expressionistOID] shouldBe "Edvard Munch"

    }
}