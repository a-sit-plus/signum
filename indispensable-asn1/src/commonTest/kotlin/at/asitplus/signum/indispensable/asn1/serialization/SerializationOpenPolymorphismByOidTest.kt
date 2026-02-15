package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.modules.SerializersModule


@OptIn(ExperimentalStdlibApi::class)
val SerializationTestOpenPolymorphismByOid by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Open-polymorphic OID dispatch round-trips with registered subtypes" {
        val der = derWithOpenByOid(includeBool = false)
        val intValue: OpenByOid = OpenByOidInt(value = 7)
        val strValue: OpenByOid = OpenByOidString(value = "hello")

        der.decodeFromDer<OpenByOid>(der.encodeToDer(intValue)) shouldBe intValue
        der.decodeFromDer<OpenByOid>(der.encodeToDer(strValue)) shouldBe strValue
    }

    "Additional OID subtype can be enabled by extending the DER serializers module" {
        val strictDer = derWithOpenByOid(includeBool = false)
        val extendedDer = derWithOpenByOid(includeBool = true)
        val boolValue: OpenByOid = OpenByOidBool(value = true)

        shouldThrow<SerializationException> {
            strictDer.encodeToDer(boolValue)
        }.message.shouldContain("No registered open-polymorphic subtype")

        val encoded = extendedDer.encodeToDer(boolValue)
        extendedDer.decodeFromDer<OpenByOid>(encoded) shouldBe boolValue

        shouldThrow<SerializationException> {
            strictDer.decodeFromDer<OpenByOid>(encoded)
        }.message.shouldContain("for OID")
    }

    "Missing OID discriminator fails decode" {
        val der = derWithOpenByOid(includeBool = false)
        val encodedNoOid = der.encodeToDer(NoOidEnvelope.serializer(), NoOidEnvelope(value = 1))
        shouldThrow<SerializationException> {
            der.decodeFromDer<OpenByOid>(encodedNoOid)
        }.message.shouldContain("Could not extract discriminator OID")
    }
}

interface OpenByOid: Identifiable

@Serializable
data class OpenByOidInt(
    val value: Int,
) : OpenByOid, Identifiable by Companion {

    companion object : Identifiable {

    override val oid: ObjectIdentifier
        get() = ObjectIdentifier("1.2.840.113549.1.1.1")
    }
}

@Serializable
data class OpenByOidString(
    val value: String,
) : OpenByOid, Identifiable by Companion {
    companion object : Identifiable {
        override val oid: ObjectIdentifier
            get() = ObjectIdentifier("1.2.840.10045.2.1")
    }
}
@Serializable
data class OpenByOidBool(
    val value: Boolean,
) : OpenByOid, Identifiable by Companion {
    companion object : Identifiable {
        override val oid: ObjectIdentifier get() = ObjectIdentifier("1.3.101.110")
    }
}

@Serializable
data class NoOidEnvelope(
    val value: Int,
)

interface OpenByNestedOid

@Serializable
data class NestedAlgorithmIdentifier(
    val oid: ObjectIdentifier,
)

@Serializable
data class OpenByNestedOidA(
    val algorithm: NestedAlgorithmIdentifier = NestedAlgorithmIdentifier(OpenByOidInt.oid),
    val payload: Int,
) : OpenByNestedOid

@Serializable
data class OpenByNestedOidB(
    val algorithm: NestedAlgorithmIdentifier = NestedAlgorithmIdentifier(OpenByOidString.oid),
    val payload: String,
) : OpenByNestedOid

private fun derWithOpenByOid(includeBool: Boolean) = DER {
    serializersModule = SerializersModule {
        polymorphicByOid(OpenByOid::class, serialName = "OpenByOid") {
            subtype<OpenByOidInt>(OpenByOidInt)
            subtype<OpenByOidString>(OpenByOidString)
            if (includeBool) {
                subtype<OpenByOidBool>(OpenByOidBool)
            }
        }
    }
}
