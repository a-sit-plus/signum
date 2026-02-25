package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.encoding.parse
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
import kotlin.time.Instant

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestInstantBridge by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Top-level kotlin.time.Instant encodes as ASN.1 UTCTime and round-trips" {
        val instant = Instant.parse("2049-12-31T23:59:59Z")
        val encoded = DER.encodeToDer(instant)
        Asn1Element.parse(encoded).tag shouldBe Asn1Element.Tag.TIME_UTC
        DER.decodeFromDer<Instant>(encoded) shouldBe instant
    }

    "Top-level kotlin.time.Instant encodes as ASN.1 GeneralizedTime after 2050 threshold" {
        val instant = Instant.parse("2051-01-01T00:00:00Z")
        val encoded = DER.encodeToDer(instant)
        Asn1Element.parse(encoded).tag shouldBe Asn1Element.Tag.TIME_GENERALIZED
        DER.decodeFromDer<Instant>(encoded) shouldBe instant
    }

    "Implicitly tagged kotlin.time.Instant property remains decodable" {
        val value = TaggedInstantBox(Instant.parse("2040-06-30T12:34:56Z"))
        val encoded = DER.encodeToDer(value)
        val childTag = (Asn1Element.parse(encoded) as Asn1Sequence).children.single().tag
        childTag shouldBe Asn1Element.Tag(
            tagValue = 0u,
            tagClass = at.asitplus.signum.indispensable.asn1.TagClass.CONTEXT_SPECIFIC,
            constructed = false
        )
        DER.decodeFromDer<TaggedInstantBox>(encoded) shouldBe value
    }

    "Nullable Instant followed by nullable Int is unambiguous" {
        val withoutInstant = NullableInstantThenInt(
            first = null,
            second = 7,
        )
        val withInstant = NullableInstantThenInt(
            first = Instant.parse("2030-01-01T00:00:00Z"),
            second = null,
        )
        DER.decodeFromDer<NullableInstantThenInt>(DER.encodeToDer(withoutInstant)) shouldBe withoutInstant
        DER.decodeFromDer<NullableInstantThenInt>(DER.encodeToDer(withInstant)) shouldBe withInstant
    }

    "Consecutive nullable Instant fields are rejected as ambiguous" {
        val value = NullableInstantThenInstant(
            first = null,
            second = Instant.parse("2030-01-01T00:00:00Z"),
        )
        shouldThrow<SerializationException> {
            DER.encodeToDer(value)
        }.message.shouldContain("Ambiguous ASN.1 layout")
    }
}

@Serializable
data class TaggedInstantBox(
    @Asn1Tag(
        tagNumber = 0u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
        constructed = Asn1ConstructedBit.PRIMITIVE,
    )
    val instant: Instant
)

@Serializable
data class NullableInstantThenInt(
    val first: Instant?,
    val second: Int?,
)

@Serializable
data class NullableInstantThenInstant(
    val first: Instant?,
    val second: Instant?,
)
