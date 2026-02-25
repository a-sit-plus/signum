package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestEncodeDefaults by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Default DER instance encodes default-valued properties" {
        val value = EncodeDefaultsSimple()
        val encoded = DER.encodeToDer(value)
        encoded.toHexString() shouldBe "30060201010c0178"
        DER.decodeFromDer<EncodeDefaultsSimple>(encoded) shouldBe value
    }

    "encodeDefaults=false omits default-valued properties" {
        val derNoDefaults = DER { encodeDefaults = false }

        val value = EncodeDefaultsSimple()
        val encoded = derNoDefaults.encodeToDer(value)
        encoded.toHexString() shouldBe "3000"
        derNoDefaults.decodeFromDer<EncodeDefaultsSimple>(encoded) shouldBe value
    }

    "encodeDefaults=false still encodes non-default values" {
        val derNoDefaults = DER { encodeDefaults = false }

        val value = EncodeDefaultsSimple(number = 2, text = "y")
        val encoded = derNoDefaults.encodeToDer(value)
        encoded.toHexString() shouldBe "30060201020c0179"
        derNoDefaults.decodeFromDer<EncodeDefaultsSimple>(encoded) shouldBe value
    }

    "encodeDefaults=false omits only defaulted fields in mixed classes" {
        val derNoDefaults = DER { encodeDefaults = false }

        val defaultsOnly = EncodeDefaultsMixed(required = 5)
        val defaultsOnlyEncoded = derNoDefaults.encodeToDer(defaultsOnly)
        defaultsOnlyEncoded.toHexString() shouldBe "3003020105"
        derNoDefaults.decodeFromDer<EncodeDefaultsMixed>(defaultsOnlyEncoded) shouldBe defaultsOnly

        val withOverrides = EncodeDefaultsMixed(required = 5, optionalInt = 8, optionalText = "a")
        val withOverridesEncoded = derNoDefaults.encodeToDer(withOverrides)
        withOverridesEncoded.toHexString() shouldBe "30090201050201080c0161"
        derNoDefaults.decodeFromDer<EncodeDefaultsMixed>(withOverridesEncoded) shouldBe withOverrides
    }
}

@Serializable
data class EncodeDefaultsSimple(
    val number: Int = 1,
    val text: String = "x",
)

@Serializable
data class EncodeDefaultsMixed(
    val required: Int,
    val optionalInt: Int = 7,
    val optionalText: String = "ok",
)
