package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException

val SerializationTutorial07AmbiguityReject by testSuite(
    testConfig = DefaultConfiguration
) {
    "Ambiguous nullable layout is rejected" {
        shouldThrow<SerializationException> {
            DER.encodeToDer(TutorialAmbiguous(first = null, second = 9))
        }.message.shouldContain("Ambiguous ASN.1 layout")
    }
}

@Serializable
private data class TutorialAmbiguous(
    val first: Int?,
    val second: Int?,
)
