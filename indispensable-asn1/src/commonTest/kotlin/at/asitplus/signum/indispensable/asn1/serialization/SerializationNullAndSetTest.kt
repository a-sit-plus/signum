package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Null
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
val SerializationTestNullAndSet by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "SET semantics" {
        val set = setOf("Foo", "Bar", "Baz")
        DER.decodeFromDer<Set<String>>(
            DER.encodeToDer(set).also { it.toHexString() shouldBe "310f0c03466f6f0c034261720c0342617a" }
        ) shouldBe set
        DER.decodeFromDer<Set<String>>(
            DER.encodeToDer(set).also { it.toHexString() shouldBe "310f0c03466f6f0c034261720c0342617a" }
        ) shouldBe set
    }

    "Nulls and Noughts" {
        val internalNullableAnnotatedOmit = InternalNullableAnnotatedOmit(null)
        val omitEncoded = DER.encodeToDer(internalNullableAnnotatedOmit).apply { toHexString() shouldBe "3000" }
        DER.decodeFromDer<InternalNullableAnnotatedOmit>(omitEncoded) shouldBe internalNullableAnnotatedOmit

        shouldThrow<SerializationException> {
            DER.encodeToDer(InternalNullableAnnotated(null))
        }
        shouldThrow<SerializationException> {
            DER.decodeFromDer<InternalNullableAnnotated>("300dbf8a39090407bf8a39039f5a00".hexToByteArray())
        }

        val internalNullableAnnotatedInt = InternalNullableAnnotatedInt(null)
        val internalNullableAnnotatedIntEncoded =
            DER.encodeToDer(internalNullableAnnotatedInt).apply { toHexString() shouldBe "300dbf8a39090407bf8a39039f5a00" }
        DER.decodeFromDer<InternalNullableAnnotatedInt>(internalNullableAnnotatedIntEncoded) shouldBe internalNullableAnnotatedInt
        val internalNullableAnnotatedIntSet = InternalNullableAnnotatedInt(5)
        DER.decodeFromDer<InternalNullableAnnotatedInt>(DER.encodeToDer(internalNullableAnnotatedIntSet)) shouldBe internalNullableAnnotatedIntSet

        val annotatedImplicit = DER.encodeToDer<NullableAnnotatedImplicit?>(null)
            .apply { toHexString(HexFormat.UpperCase) shouldBe "BF8A39090407BF8A39039F5A00" }
        DER.decodeFromDer<NullableAnnotatedImplicit?>(annotatedImplicit) shouldBe null

        DER.encodeToDer<Nullable?>(null) shouldBe Asn1Null.derEncoded

        val nullable: String? = null
        DER.encodeToDer(nullable) shouldBe byteArrayOf()
        DER.decodeFromDer<String?>(byteArrayOf()) shouldBe null

        DER.encodeToDer<NullableAnnotatedImplicitOmit?>(null) shouldBe byteArrayOf()
        DER.decodeFromDer<NullableAnnotatedImplicitOmit?>(byteArrayOf()) shouldBe null

        val annotated = DER.encodeToDer<NullableAnnotated?>(null)
            .apply { toHexString(HexFormat.UpperCase) shouldBe "0406BF8A39020500" }
        DER.decodeFromDer<NullableAnnotated?>(annotated) shouldBe null

        // Regression: empty primitive values must not be mistaken for null when encodeNull=false.
        val emptyString = NullablePlainString("")
        DER.decodeFromDer<NullablePlainString>(DER.encodeToDer(emptyString)) shouldBe emptyString

        val nullString = NullablePlainString(null)
        DER.decodeFromDer<NullablePlainString>(DER.encodeToDer(nullString)) shouldBe nullString
    }
}

@Serializable
@Asn1nnotation(encodeNull = true)
object Nullable

@Serializable
@Asn1nnotation(
    Layer(Type.OCTET_STRING),
    Layer(Type.EXPLICIT_TAG, 1337uL),
    encodeNull = true
)
object NullableAnnotated

@Serializable
@Asn1nnotation(
    Layer(Type.EXPLICIT_TAG, 1337uL),
    Layer(Type.OCTET_STRING),
    Layer(Type.EXPLICIT_TAG, 1337uL),
    Layer(Type.IMPLICIT_TAG, 90uL),
    encodeNull = true
)
object NullableAnnotatedImplicit

@Serializable
@Asn1nnotation(
    Layer(Type.EXPLICIT_TAG, 1337uL),
    Layer(Type.OCTET_STRING),
    Layer(Type.EXPLICIT_TAG, 1337uL),
    Layer(Type.IMPLICIT_TAG, 90uL),
)
object NullableAnnotatedImplicitOmit

@Serializable
data class InternalNullableAnnotated(
    @Asn1nnotation(
        Layer(Type.EXPLICIT_TAG, 1337uL),
        Layer(Type.OCTET_STRING),
        Layer(Type.EXPLICIT_TAG, 1337uL),
        Layer(Type.IMPLICIT_TAG, 90uL),
        encodeNull = true
    )
    val nullable: String?
)

@Serializable
data class InternalNullableAnnotatedOmit(
    @Asn1nnotation(
        Layer(Type.EXPLICIT_TAG, 1337uL),
        Layer(Type.OCTET_STRING),
        Layer(Type.EXPLICIT_TAG, 1337uL),
        Layer(Type.IMPLICIT_TAG, 90uL),
    )
    val nullable: String?
)

@Serializable
data class InternalNullableAnnotatedInt(
    @Asn1nnotation(
        Layer(Type.EXPLICIT_TAG, 1337uL),
        Layer(Type.OCTET_STRING),
        Layer(Type.EXPLICIT_TAG, 1337uL),
        Layer(Type.IMPLICIT_TAG, 90uL),
        encodeNull = true
    )
    val nullable: Int?
)

@Serializable
data class NullablePlainString(
    val value: String?
)
