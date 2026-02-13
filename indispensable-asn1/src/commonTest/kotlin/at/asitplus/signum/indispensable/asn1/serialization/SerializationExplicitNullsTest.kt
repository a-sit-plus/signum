package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestExplicitNulls by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "explicitNulls=false omits nullable null properties" {
        val derImplicitNulls = DER { explicitNulls = false }
        val value = ExplicitNullsSingleNullable(null)

        val encoded = derImplicitNulls.encodeToDer(value)
        encoded.toHexString() shouldBe "3000"
        derImplicitNulls.decodeFromDer<ExplicitNullsSingleNullable>(encoded) shouldBe value
    }

    "explicitNulls=true encodes nullable null properties as ASN.1 NULL" {
        val derExplicitNulls = DER { explicitNulls = true }
        val value = ExplicitNullsSingleNullable(null)

        val encoded = derExplicitNulls.encodeToDer(value)
        encoded.toHexString() shouldBe "30020500"
        derExplicitNulls.decodeFromDer<ExplicitNullsSingleNullable>(encoded) shouldBe value
    }

    "explicitNulls=true disambiguates otherwise-ambiguous nullable omission layouts" {
        val derExplicitNulls = DER { explicitNulls = true }
        val value = AmbiguousNullableStringLayout(
            first = "first",
            second = null,
            third = "third",
        )

        val encoded = derExplicitNulls.encodeToDer(value)
        encoded.toHexString() shouldBe "30100c05666972737405000c057468697264"
        derExplicitNulls.decodeFromDer<AmbiguousNullableStringLayout>(encoded) shouldBe value
    }
}

@Serializable
data class ExplicitNullsSingleNullable(
    val value: String?,
)

