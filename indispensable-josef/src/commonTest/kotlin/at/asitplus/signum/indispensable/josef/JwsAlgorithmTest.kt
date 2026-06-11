package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement

val digestBugTest by matrixSuite {
    data(JwsAlgorithm.Signature.entries) test {
        val json = joseCompliantSerializer.encodeToJsonElement(it)
        val decoded = joseCompliantSerializer.decodeFromJsonElement<JwsAlgorithm.Signature>(json)
        decoded.digest shouldBe it.digest
    }
}