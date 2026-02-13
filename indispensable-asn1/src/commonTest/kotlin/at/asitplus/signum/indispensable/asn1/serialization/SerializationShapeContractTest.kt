package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1Primitive
import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestShapeContract by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Nullable raw ASN.1 element in the middle is rejected as undecidable" {
        val value = AmbiguousMiddleNullableRawAsn1(
            prefix = 1,
            extension = null,
            suffix = 2
        )
        shouldThrow<SerializationException> {
            DER.encodeToDer(value)
        }
        shouldThrow<SerializationException> {
            DER.decodeFromDer<AmbiguousMiddleNullableRawAsn1>("3006020101020102".hexToByteArray())
        }
    }

    "Explicitly tagged nullable raw ASN.1 element in the middle is deterministic" {
        val withoutExtension = DisambiguatedMiddleNullableRawAsn1(
            prefix = 1,
            extension = null,
            suffix = 2
        )
        DER.decodeFromDer<DisambiguatedMiddleNullableRawAsn1>(DER.encodeToDer(withoutExtension)) shouldBe withoutExtension

        val withExtension = DisambiguatedMiddleNullableRawAsn1(
            prefix = 1,
            extension = Asn1Explicit(99.encodeToAsn1Primitive()),
            suffix = 2
        )
        DER.decodeFromDer<DisambiguatedMiddleNullableRawAsn1>(DER.encodeToDer(withExtension)) shouldBe withExtension
    }

    "Trailing nullable raw ASN.1 element remains supported" {
        val withoutExtension = TrailingNullableRawAsn1(
            prefix = 7,
            extension = null
        )
        DER.decodeFromDer<TrailingNullableRawAsn1>(DER.encodeToDer(withoutExtension)) shouldBe withoutExtension

        val withExtension = TrailingNullableRawAsn1(
            prefix = 7,
            extension = 11.encodeToAsn1Primitive()
        )
        DER.decodeFromDer<TrailingNullableRawAsn1>(DER.encodeToDer(withExtension)) shouldBe withExtension
    }
}

@Serializable
data class AmbiguousMiddleNullableRawAsn1(
    val prefix: Int,
    val extension: Asn1Element?,
    val suffix: Int,
)

@Serializable
data class DisambiguatedMiddleNullableRawAsn1(
    val prefix: Int,
    @Asn1Tag(tagNumber = 0, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, constructed = Asn1ConstructedBit.CONSTRUCTED)
    val extension: Asn1Explicit<Asn1Element>?,
    val suffix: Int,
)

@Serializable
data class TrailingNullableRawAsn1(
    val prefix: Int,
    val extension: Asn1Element?,
)
