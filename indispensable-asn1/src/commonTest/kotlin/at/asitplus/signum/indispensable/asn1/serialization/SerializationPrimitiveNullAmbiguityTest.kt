package at.asitplus.signum.indispensable.asn1.serialization

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
val SerializationTestPrimitiveNullAmbiguity by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Implicit+encodeNull is rejected for empty-capable primitives" {
        shouldThrow<SerializationException> { DER.encodeToDer(PrimitiveImplicitStringAmbiguous(null)) }
        shouldThrow<SerializationException> { DER.decodeFromDer<PrimitiveImplicitStringAmbiguous>("3000".hexToByteArray()) }

        shouldThrow<SerializationException> { DER.encodeToDer(PrimitiveImplicitFloatAmbiguous(null)) }
        shouldThrow<SerializationException> { DER.decodeFromDer<PrimitiveImplicitFloatAmbiguous>("3000".hexToByteArray()) }

        shouldThrow<SerializationException> { DER.encodeToDer(PrimitiveImplicitDoubleAmbiguous(null)) }
        shouldThrow<SerializationException> { DER.decodeFromDer<PrimitiveImplicitDoubleAmbiguous>("3000".hexToByteArray()) }

        shouldThrow<SerializationException> { DER.encodeToDer(PrimitiveImplicitOctetStringAmbiguous(null)) }
        shouldThrow<SerializationException> { DER.decodeFromDer<PrimitiveImplicitOctetStringAmbiguous>("3000".hexToByteArray()) }
    }

    "Implicit+encodeNull is accepted for non-empty-capable primitives" {
        val longNull = PrimitiveImplicitLongSafe(null)
        DER.decodeFromDer<PrimitiveImplicitLongSafe>(DER.encodeToDer(longNull)) shouldBe longNull
        val longSet = PrimitiveImplicitLongSafe(7L)
        DER.decodeFromDer<PrimitiveImplicitLongSafe>(DER.encodeToDer(longSet)) shouldBe longSet

        val intNull = PrimitiveImplicitIntSafe(null)
        DER.decodeFromDer<PrimitiveImplicitIntSafe>(DER.encodeToDer(intNull)) shouldBe intNull
        val intSet = PrimitiveImplicitIntSafe(7)
        DER.decodeFromDer<PrimitiveImplicitIntSafe>(DER.encodeToDer(intSet)) shouldBe intSet

        val shortNull = PrimitiveImplicitShortSafe(null)
        DER.decodeFromDer<PrimitiveImplicitShortSafe>(DER.encodeToDer(shortNull)) shouldBe shortNull
        val shortSet = PrimitiveImplicitShortSafe(7)
        DER.decodeFromDer<PrimitiveImplicitShortSafe>(DER.encodeToDer(shortSet)) shouldBe shortSet
    }

    "No implicit tags remain unambiguous for empty-capable primitives" {
        val stringNull = PrimitiveNoImplicitStringSafe(null)
        DER.decodeFromDer<PrimitiveNoImplicitStringSafe>(DER.encodeToDer(stringNull)) shouldBe stringNull
        val stringEmpty = PrimitiveNoImplicitStringSafe("")
        DER.decodeFromDer<PrimitiveNoImplicitStringSafe>(DER.encodeToDer(stringEmpty)) shouldBe stringEmpty

        val floatNull = PrimitiveNoImplicitFloatSafe(null)
        DER.decodeFromDer<PrimitiveNoImplicitFloatSafe>(DER.encodeToDer(floatNull)) shouldBe floatNull
        val floatZero = PrimitiveNoImplicitFloatSafe(0f)
        DER.decodeFromDer<PrimitiveNoImplicitFloatSafe>(DER.encodeToDer(floatZero)) shouldBe floatZero

        val doubleNull = PrimitiveNoImplicitDoubleSafe(null)
        DER.decodeFromDer<PrimitiveNoImplicitDoubleSafe>(DER.encodeToDer(doubleNull)) shouldBe doubleNull
        val doubleZero = PrimitiveNoImplicitDoubleSafe(0.0)
        DER.decodeFromDer<PrimitiveNoImplicitDoubleSafe>(DER.encodeToDer(doubleZero)) shouldBe doubleZero
    }

    "Explicit wrapper does not rescue an inner ambiguous primitive/null encoding" {
        shouldThrow<SerializationException> {
            DER.encodeToDer(
                PrimitiveImplicitThenExplicitStringSafe(
                    Asn1Explicit(PrimitiveInnerImplicitNullableString(null))
                )
            )
        }
        shouldThrow<SerializationException> {
            DER.decodeFromDer<PrimitiveImplicitThenExplicitStringSafe>("3000".hexToByteArray())
        }
    }

    "Octet wrapping without implicit tagging remains unambiguous" {
        val valueNull = PrimitiveOctetStringSafe(
            Asn1OctetWrapped(PrimitiveInnerPlainNullableString(null))
        )
        DER.decodeFromDer<PrimitiveOctetStringSafe>(DER.encodeToDer(valueNull)) shouldBe valueNull

        val valueEmpty = PrimitiveOctetStringSafe(
            Asn1OctetWrapped(PrimitiveInnerPlainNullableString(""))
        )
        DER.decodeFromDer<PrimitiveOctetStringSafe>(DER.encodeToDer(valueEmpty)) shouldBe valueEmpty

        val octetsNull = PrimitiveNoImplicitOctetStringSafe(null)
        val decodedOctetsNull = DER.decodeFromDer<PrimitiveNoImplicitOctetStringSafe>(DER.encodeToDer(octetsNull))
        decodedOctetsNull.value shouldBe null

        val octetsEmpty = PrimitiveNoImplicitOctetStringSafe(byteArrayOf())
        val decodedOctetsEmpty = DER.decodeFromDer<PrimitiveNoImplicitOctetStringSafe>(DER.encodeToDer(octetsEmpty))
        decodedOctetsEmpty.value?.toList() shouldBe octetsEmpty.value?.toList()
    }

    "Octet wrapping does not disambiguate if implicit remains innermost" {
        shouldThrow<SerializationException> {
            DER.encodeToDer(
                PrimitiveOctetThenImplicitStringAmbiguous(
                    Asn1OctetWrapped(PrimitiveInnerImplicitNullableString41(null))
                )
            )
        }
        shouldThrow<SerializationException> {
            DER.decodeFromDer<PrimitiveOctetThenImplicitStringAmbiguous>("3000".hexToByteArray())
        }
    }

    "Bit string with implicit+encodeNull remains unambiguous" {
        val valueNull = PrimitiveImplicitBitStringSafe(null)
        val encodedNull = DER.encodeToDer(valueNull)
        val decodedNull = DER.decodeFromDer<PrimitiveImplicitBitStringSafe>(encodedNull)
        decodedNull.value shouldBe null

        val valueSet = PrimitiveImplicitBitStringSafe(byteArrayOf(0x01, 0x02))
        val encodedSet = DER.encodeToDer(valueSet)
        val decodedSet = DER.decodeFromDer<PrimitiveImplicitBitStringSafe>(encodedSet)
        decodedSet.value?.toList() shouldBe valueSet.value?.toList()
    }
}

@Serializable
data class PrimitiveImplicitStringAmbiguous(
    @Asn1nnotation(tagNumber = 10, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, encodeNull = true)
    val value: String?
)

@Serializable
data class PrimitiveImplicitFloatAmbiguous(
    @Asn1nnotation(tagNumber = 11, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, encodeNull = true)
    val value: Float?
)

@Serializable
data class PrimitiveImplicitDoubleAmbiguous(
    @Asn1nnotation(tagNumber = 12, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, encodeNull = true)
    val value: Double?
)

@Serializable
data class PrimitiveImplicitOctetStringAmbiguous(
    @Asn1nnotation(tagNumber = 13, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, encodeNull = true)
    val value: ByteArray?
)

@Serializable
data class PrimitiveImplicitLongSafe(
    @Asn1nnotation(tagNumber = 20, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, encodeNull = true)
    val value: Long?
)

@Serializable
data class PrimitiveImplicitIntSafe(
    @Asn1nnotation(tagNumber = 21, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, encodeNull = true)
    val value: Int?
)

@Serializable
data class PrimitiveImplicitShortSafe(
    @Asn1nnotation(tagNumber = 22, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, encodeNull = true)
    val value: Short?
)

@Serializable
data class PrimitiveNoImplicitStringSafe(
    @Asn1nnotation(encodeNull = true)
    val value: String?
)

@Serializable
data class PrimitiveNoImplicitFloatSafe(
    @Asn1nnotation(encodeNull = true)
    val value: Float?
)

@Serializable
data class PrimitiveNoImplicitDoubleSafe(
    @Asn1nnotation(encodeNull = true)
    val value: Double?
)

@Serializable
data class PrimitiveImplicitThenExplicitStringSafe(
    @Asn1nnotation(
        tagNumber = 31,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
        constructed = Asn1ConstructedBit.CONSTRUCTED,
    )
    val value: Asn1Explicit<PrimitiveInnerImplicitNullableString>
)

@Serializable
data class PrimitiveInnerImplicitNullableString(
    @Asn1nnotation(
        tagNumber = 30,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
        encodeNull = true,
    )
    val value: String?
)

@Serializable
data class PrimitiveOctetStringSafe(
    val value: Asn1OctetWrapped<PrimitiveInnerPlainNullableString>
)

@Serializable
data class PrimitiveInnerPlainNullableString(
    @Asn1nnotation(encodeNull = true)
    val value: String?
)

@Serializable
data class PrimitiveNoImplicitOctetStringSafe(
    @Asn1nnotation(encodeNull = true)
    val value: ByteArray?
)

@Serializable
data class PrimitiveOctetThenImplicitStringAmbiguous(
    val value: Asn1OctetWrapped<PrimitiveInnerImplicitNullableString41>
)

@Serializable
data class PrimitiveInnerImplicitNullableString41(
    @Asn1nnotation(
        tagNumber = 41,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
        encodeNull = true,
    )
    val value: String?
)

@Serializable
data class PrimitiveImplicitBitStringSafe(
    @Asn1nnotation(
        tagNumber = 50,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
        asBitString = true,
        encodeNull = true,
    )
    val value: ByteArray?
)
