package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.github.aakira.napier.log
import io.kotest.matchers.collections.shouldNotBeEmpty

@OptIn(ExperimentalPkiApi::class)
val systemTruststoreTest by testSuite {
    "System Trust Store" - {
        "can be loaded" {
            SystemTrustStore.isNotEmpty()
        }
        "and is not empty" {
            SystemTrustStore.shouldNotBeEmpty()
            println("System TrustStore loaded with ${SystemTrustStore.size} trust anchors" )
        }

    }
}