package at.asitplus.signum.indispensable.asn1.serialization

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
    val derExplicitNulls = DER { explicitNulls = true }

    "Implicit+explicitNulls is rejected for empty-capable primitives" {
        shouldThrow<SerializationException> { derExplicitNulls.encodeToDer(PrimitiveImplicitStringAmbiguous(null)) }
        shouldThrow<SerializationException> { derExplicitNulls.decodeFromDer<PrimitiveImplicitStringAmbiguous>("3000".hexToByteArray()) }

        shouldThrow<SerializationException> { derExplicitNulls.encodeToDer(PrimitiveImplicitFloatAmbiguous(null)) }
        shouldThrow<SerializationException> { derExplicitNulls.decodeFromDer<PrimitiveImplicitFloatAmbiguous>("3000".hexToByteArray()) }

        shouldThrow<SerializationException> { derExplicitNulls.encodeToDer(PrimitiveImplicitDoubleAmbiguous(null)) }
        shouldThrow<SerializationException> { derExplicitNulls.decodeFromDer<PrimitiveImplicitDoubleAmbiguous>("3000".hexToByteArray()) }

        shouldThrow<SerializationException> { derExplicitNulls.encodeToDer(PrimitiveImplicitOctetStringAmbiguous(null)) }
        shouldThrow<SerializationException> {
            derExplicitNulls.decodeFromDer<PrimitiveImplicitOctetStringAmbiguous>("3000".hexToByteArray())
        }
    }

    "Implicit+explicitNulls is accepted for non-empty-capable primitives" {
        val longNull = PrimitiveImplicitLongSafe(null)
        derExplicitNulls.decodeFromDer<PrimitiveImplicitLongSafe>(derExplicitNulls.encodeToDer(longNull)) shouldBe longNull
        val longSet = PrimitiveImplicitLongSafe(7L)
        derExplicitNulls.decodeFromDer<PrimitiveImplicitLongSafe>(derExplicitNulls.encodeToDer(longSet)) shouldBe longSet

        val intNull = PrimitiveImplicitIntSafe(null)
        derExplicitNulls.decodeFromDer<PrimitiveImplicitIntSafe>(derExplicitNulls.encodeToDer(intNull)) shouldBe intNull
        val intSet = PrimitiveImplicitIntSafe(7)
        derExplicitNulls.decodeFromDer<PrimitiveImplicitIntSafe>(derExplicitNulls.encodeToDer(intSet)) shouldBe intSet

        val shortNull = PrimitiveImplicitShortSafe(null)
        derExplicitNulls.decodeFromDer<PrimitiveImplicitShortSafe>(derExplicitNulls.encodeToDer(shortNull)) shouldBe shortNull
        val shortSet = PrimitiveImplicitShortSafe(7)
        derExplicitNulls.decodeFromDer<PrimitiveImplicitShortSafe>(derExplicitNulls.encodeToDer(shortSet)) shouldBe shortSet
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
            derExplicitNulls.encodeToDer(
                PrimitiveImplicitThenExplicitStringSafe(
                    ExplicitlyTagged(PrimitiveInnerImplicitNullableString(null))
                )
            )
        }
        shouldThrow<SerializationException> {
            derExplicitNulls.decodeFromDer<PrimitiveImplicitThenExplicitStringSafe>("3000".hexToByteArray())
        }
    }

    "Octet wrapping without implicit tagging remains unambiguous" {
        val valueNull = PrimitiveOctetStringSafe(
            OctetStringEncapsulated(PrimitiveInnerPlainNullableString(null))
        )
        DER.decodeFromDer<PrimitiveOctetStringSafe>(DER.encodeToDer(valueNull)) shouldBe valueNull

        val valueEmpty = PrimitiveOctetStringSafe(
            OctetStringEncapsulated(PrimitiveInnerPlainNullableString(""))
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
            derExplicitNulls.encodeToDer(
                PrimitiveOctetThenImplicitStringAmbiguous(
                    OctetStringEncapsulated(PrimitiveInnerImplicitNullableString41(null))
                )
            )
        }
        shouldThrow<SerializationException> {
            derExplicitNulls.decodeFromDer<PrimitiveOctetThenImplicitStringAmbiguous>("3000".hexToByteArray())
        }
    }

    "Bit string with implicit+explicitNulls remains unambiguous" {
        val valueNull = PrimitiveImplicitBitStringSafe(null)
        val encodedNull = derExplicitNulls.encodeToDer(valueNull)
        val decodedNull = derExplicitNulls.decodeFromDer<PrimitiveImplicitBitStringSafe>(encodedNull)
        decodedNull.value shouldBe null

        val valueSet = PrimitiveImplicitBitStringSafe(byteArrayOf(0x01, 0x02))
        val encodedSet = derExplicitNulls.encodeToDer(valueSet)
        val decodedSet = derExplicitNulls.decodeFromDer<PrimitiveImplicitBitStringSafe>(encodedSet)
        decodedSet.value?.toList() shouldBe valueSet.value?.toList()
    }
}

@Serializable
data class PrimitiveImplicitStringAmbiguous(
    @Asn1Tag(tagNumber = 10u)
    val value: String?
)

@Serializable
data class PrimitiveImplicitFloatAmbiguous(
    @Asn1Tag(tagNumber = 11u)
    val value: Float?
)

@Serializable
data class PrimitiveImplicitDoubleAmbiguous(
    @Asn1Tag(tagNumber = 12u)
    val value: Double?
)

@Serializable
data class PrimitiveImplicitOctetStringAmbiguous(
    @Asn1Tag(tagNumber = 13u)
    val value: ByteArray?
)

@Serializable
data class PrimitiveImplicitLongSafe(
    @Asn1Tag(tagNumber = 20u)
    val value: Long?
)

@Serializable
data class PrimitiveImplicitIntSafe(
    @Asn1Tag(tagNumber = 21u)
    val value: Int?
)

@Serializable
data class PrimitiveImplicitShortSafe(
    @Asn1Tag(tagNumber = 22u)
    val value: Short?
)

@Serializable
data class PrimitiveNoImplicitStringSafe(
    val value: String?
)

@Serializable
data class PrimitiveNoImplicitFloatSafe(
    val value: Float?
)

@Serializable
data class PrimitiveNoImplicitDoubleSafe(
    val value: Double?
)

@Serializable
data class PrimitiveImplicitThenExplicitStringSafe(
    @Asn1Tag(
        tagNumber = 31u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
        constructed = Asn1ConstructedBit.CONSTRUCTED,
    )
    val value: ExplicitlyTagged<PrimitiveInnerImplicitNullableString>
)

@Serializable
data class PrimitiveInnerImplicitNullableString(
    @Asn1Tag(
        tagNumber = 30u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    )
    val value: String?
)

@Serializable
data class PrimitiveOctetStringSafe(
    val value: OctetStringEncapsulated<PrimitiveInnerPlainNullableString>
)

@Serializable
data class PrimitiveInnerPlainNullableString(
    val value: String?
)

@Serializable
data class PrimitiveNoImplicitOctetStringSafe(
    val value: ByteArray?
)

@Serializable
data class PrimitiveOctetThenImplicitStringAmbiguous(
    val value: OctetStringEncapsulated<PrimitiveInnerImplicitNullableString41>
)

@Serializable
data class PrimitiveInnerImplicitNullableString41(
    @Asn1Tag(
        tagNumber = 41u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    )
    val value: String?
)

@Serializable
data class PrimitiveImplicitBitStringSafe(
    @Asn1BitString
    @Asn1Tag(
        tagNumber = 50u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    )
    val value: ByteArray?
)
