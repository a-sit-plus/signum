package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestAsn1String by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "String" {
        val str = Asn1String.UTF8("foo")
        val serialized = DER.encodeToDer(str)

        DER.decodeFromDer<Asn1String>(serialized) shouldBe str
        DER.decodeFromDer<Asn1String.UTF8>(serialized) shouldBe str
    }
}
