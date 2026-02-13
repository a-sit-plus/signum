package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestImplicitTagging by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Implicit tagging" - {
        val imlNothing = DER.encodeToDer(NothingOnClass("foo"))
        val imlClass = DER.encodeToDer(ImplicitOnClass("foo"))
        val imlProp = DER.encodeToDer(ImplicitOnProperty("foo"))
        val imlBoth = DER.encodeToDer(ImplicitOnBoth("foo"))

        DER.decodeFromDer<NothingOnClass>(imlNothing) shouldBe NothingOnClass("foo")
        DER.decodeFromDer<ImplicitOnClass>(imlClass) shouldBe ImplicitOnClass("foo")
        DER.decodeFromDer<ImplicitOnProperty>(imlProp) shouldBe ImplicitOnProperty("foo")
        DER.decodeFromDer<ImplicitOnBoth>(imlBoth) shouldBe ImplicitOnBoth("foo")

        shouldThrow<SerializationException> { DER.decodeFromDer<ImplicitOnProperty>(imlClass) }
        shouldThrow<SerializationException> { DER.decodeFromDer<ImplicitOnProperty>(imlBoth) }
        shouldThrow<SerializationException> { DER.decodeFromDer<ImplicitOnProperty>(imlNothing) }

        shouldThrow<SerializationException> { DER.decodeFromDer<ImplicitOnClass>(imlNothing) }
        shouldThrow<SerializationException> { DER.decodeFromDer<ImplicitOnClass>(imlBoth) }
        shouldThrow<SerializationException> { DER.decodeFromDer<ImplicitOnClass>(imlProp) }

        shouldThrow<SerializationException> { DER.decodeFromDer<ImplicitOnBoth>(imlProp) }
        shouldThrow<SerializationException> { DER.decodeFromDer<ImplicitOnBoth>(imlClass) }
        shouldThrow<SerializationException> { DER.decodeFromDer<ImplicitOnBoth>(imlNothing) }

        shouldThrow<SerializationException> { DER.decodeFromDer<NothingOnClass>(imlClass) }
        shouldThrow<SerializationException> { DER.decodeFromDer<NothingOnClass>(imlProp) }
        shouldThrow<SerializationException> { DER.decodeFromDer<NothingOnClass>(imlBoth) }

        shouldThrow<SerializationException> { DER.decodeFromDer<ImplicitOnClassWrong>(imlClass) }
        shouldThrow<SerializationException> { DER.decodeFromDer<ImplicitOnPropertyWrong>(imlProp) }
        shouldThrow<SerializationException> { DER.decodeFromDer<ImplicitOnBothWrong>(imlBoth) }
        shouldThrow<SerializationException> { DER.decodeFromDer<ImplicitOnBothWrongClass>(imlBoth) }
        shouldThrow<SerializationException> { DER.decodeFromDer<ImplicitOnBothWrongProperty>(imlBoth) }

        "Nested" {
            val nothingOnClassNested = DER.encodeToDer(NothingOnClassNested(NothingOnClass("foo")))
            val nothingOnClassNestedOnClass = DER.encodeToDer(NothingOnClassNestedOnClass(ImplicitOnClass("foo")))
            val nothingOnClassNestedOnProperty = DER.encodeToDer(NothingOnClassNestedOnProperty(NothingOnClass("foo")))
            val nothingOnClassNestedOnPropertyOverride =
                DER.encodeToDer(NothingOnClassNestedOnPropertyOverride(ImplicitOnClass("foo")))

            nothingOnClassNested.toHexString() shouldBe "300730050c03666f6f"
            nothingOnClassNestedOnClass.toHexString() shouldBe "3009bf8a39050c03666f6f"
            nothingOnClassNestedOnProperty.toHexString() shouldBe "3009bf8a39050c03666f6f"
            nothingOnClassNestedOnPropertyOverride.toHexString() shouldBe "3009bf851a050c03666f6f"

            DER.decodeFromDer<NothingOnClassNested>(nothingOnClassNested)
            DER.decodeFromDer<NothingOnClassNestedOnClass>(nothingOnClassNestedOnClass)
            DER.decodeFromDer<NothingOnClassNestedOnClass>(nothingOnClassNestedOnProperty)
            DER.decodeFromDer<NothingOnClassNestedOnProperty>(nothingOnClassNestedOnProperty)
            DER.decodeFromDer<NothingOnClassNestedOnProperty>(nothingOnClassNestedOnClass)

            DER.decodeFromDer<NothingOnClassNestedOnPropertyOverride>(nothingOnClassNestedOnPropertyOverride)

            shouldThrow<SerializationException> { DER.decodeFromDer<NothingOnClassNested>(nothingOnClassNestedOnClass) }
            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNested>(nothingOnClassNestedOnProperty)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNested>(nothingOnClassNestedOnPropertyOverride)
            }

            shouldThrow<SerializationException> { DER.decodeFromDer<NothingOnClassNestedOnClass>(nothingOnClassNested) }
            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnClass>(nothingOnClassNestedOnPropertyOverride)
            }

            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnProperty>(nothingOnClassNested)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnProperty>(nothingOnClassNestedOnPropertyOverride)
            }

            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyOverride>(nothingOnClassNested)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyOverride>(nothingOnClassNestedOnProperty)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyOverride>(nothingOnClassNestedOnClass)
            }

            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnClassWrong>(nothingOnClassNested)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnClassWrong>(nothingOnClassNestedOnClass)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnClassWrong>(nothingOnClassNestedOnProperty)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnClassWrong>(nothingOnClassNestedOnPropertyOverride)
            }

            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyWrong>(nothingOnClassNested)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyWrong>(nothingOnClassNestedOnClass)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyWrong>(nothingOnClassNestedOnProperty)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyWrong>(nothingOnClassNestedOnPropertyOverride)
            }

            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyOverrideWrong>(nothingOnClassNested)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyOverrideWrong>(nothingOnClassNestedOnClass)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyOverrideWrong>(nothingOnClassNestedOnProperty)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromDer<NothingOnClassNestedOnPropertyOverrideWrong>(nothingOnClassNestedOnPropertyOverride)
            }
        }
    }
}

@Serializable
data class NothingOnClass(val a: String)

@Serializable
@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 1337uL))
data class ImplicitOnClass(val a: String)

@Serializable
@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 7331uL))
data class ImplicitOnClassWrong(val a: String)

@Serializable
data class ImplicitOnProperty(@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 1338uL)) val a: String)

@Serializable
data class ImplicitOnPropertyWrong(@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 8331uL)) val a: String)

@Serializable
@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 1337uL))
data class ImplicitOnBoth(@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 1338uL)) val a: String)

@Serializable
@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 73331uL))
data class ImplicitOnBothWrong(@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 8331uL)) val a: String)

@Serializable
@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 7331uL))
data class ImplicitOnBothWrongClass(@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 1338uL)) val a: String)

@Serializable
@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 1337uL))
data class ImplicitOnBothWrongProperty(@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 8331uL)) val a: String)

@Serializable
data class NothingOnClassNested(val a: NothingOnClass)

@Serializable
data class NothingOnClassNestedOnClass(val a: ImplicitOnClass)

@Serializable
data class NothingOnClassNestedOnClassWrong(val a: ImplicitOnClassWrong)

@Serializable
data class NothingOnClassNestedOnProperty(@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 1337uL)) val a: NothingOnClass)

@Serializable
data class NothingOnClassNestedOnPropertyWrong(@Asn1nnotation(Layer(Type.IMPLICIT_TAG, 333uL)) val a: NothingOnClass)

@Serializable
data class NothingOnClassNestedOnPropertyOverride(
    @Asn1nnotation(
        Layer(
            Type.IMPLICIT_TAG,
            666uL
        )
    ) val a: ImplicitOnClass
)

@Serializable
data class NothingOnClassNestedOnPropertyOverrideWrong(
    @Asn1nnotation(
        Layer(
            Type.IMPLICIT_TAG,
            999uL
        )
    ) val a: ImplicitOnClass
)

@Serializable
@Asn1nnotation(
    Layer(Type.IMPLICIT_TAG, 1337uL),
    Layer(Type.OCTET_STRING),
)
class OuterTagInnerOctet

@Serializable
@Asn1nnotation(
    Layer(Type.IMPLICIT_TAG, 1342uL),
    Layer(Type.EXPLICIT_TAG, 1341uL),
    Layer(Type.EXPLICIT_TAG, 1340uL),
    Layer(Type.OCTET_STRING),
    Layer(Type.EXPLICIT_TAG, 1339uL),
    Layer(Type.IMPLICIT_TAG, 1337uL),
    Layer(Type.IMPLICIT_TAG, 1336uL),
)
class OuterOctetInnerTag
