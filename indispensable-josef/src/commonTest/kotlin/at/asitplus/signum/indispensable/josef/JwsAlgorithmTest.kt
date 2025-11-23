package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement

val digestBugTest by testSuite {
    withData(JwsAlgorithm.Signature.entries) {
        val json = joseCompliantSerializer.encodeToJsonElement(it)
        val decoded = joseCompliantSerializer.decodeFromJsonElement<JwsAlgorithm.Signature>(json)
        decoded.digest shouldBe it.digest
    }
}