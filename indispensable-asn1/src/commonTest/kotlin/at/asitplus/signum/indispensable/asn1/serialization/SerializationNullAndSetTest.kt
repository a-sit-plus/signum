package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Null
import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestNullAndSet by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "SET semantics" {
        val set = setOf("Foo", "Bar", "Baz")
        DER.decodeFromDer<Set<String>>(
            DER.encodeToDer(set).also { it.toHexString() shouldBe "310f0c03466f6f0c034261720c0342617a" }
        ) shouldBe set
    }

    "Nulls and Noughts" {
        DER.encodeToDer<NullAsAsn1Null?>(null) shouldBe Asn1Null.derEncoded

        val nullable: String? = null
        DER.encodeToDer(nullable) shouldBe byteArrayOf()
        DER.decodeFromDer<String?>(byteArrayOf()) shouldBe null

        val taggedNull = TaggedNullableInt(value = null)
        DER.decodeFromDer<TaggedNullableInt>(DER.encodeToDer(taggedNull)) shouldBe taggedNull

        val taggedValue = TaggedNullableInt(value = 5)
        DER.decodeFromDer<TaggedNullableInt>(DER.encodeToDer(taggedValue)) shouldBe taggedValue

        val omitted = TaggedNullableIntOmit(value = null)
        DER.decodeFromDer<TaggedNullableIntOmit>(DER.encodeToDer(omitted)) shouldBe omitted

        // Regression: empty primitive values must not be mistaken for null when encodeNull=false.
        val emptyString = NullablePlainString("")
        DER.decodeFromDer<NullablePlainString>(DER.encodeToDer(emptyString)) shouldBe emptyString

        val nullString = NullablePlainString(null)
        DER.decodeFromDer<NullablePlainString>(DER.encodeToDer(nullString)) shouldBe nullString
    }
}

@Serializable
@Asn1EncodeNull
object NullAsAsn1Null

@Serializable
data class TaggedNullableInt(
    @Asn1EncodeNull
    @Asn1Tag(
        tagNumber = 90,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    )
    val value: Int?
)

@Serializable
data class TaggedNullableIntOmit(
    @Asn1Tag(
        tagNumber = 90,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    )
    val value: Int?
)

@Serializable
data class NullablePlainString(
    val value: String?
)
