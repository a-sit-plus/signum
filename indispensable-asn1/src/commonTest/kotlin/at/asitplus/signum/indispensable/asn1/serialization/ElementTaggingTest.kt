package io.kotest.property.at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.serialization.*
import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Transient
import kotlin.jvm.JvmInline


val TaggedTest by testSuite {
    withData(0, 2, 3, 4, 5, 6, 7, 8, 9) - { int ->
        "UntaggedInt" {
            DER.encodeToDer(UntaggedInt(int)).toHexString() shouldBe "300302010$int".also {
                DER.decodeFromDer<UntaggedInt>(it.hexToByteArray()) shouldBe UntaggedInt(
                    int
                )
            }
        }
        "UntaggedAsn1Integer" {

            DER.encodeToDer(UntaggedAsn1Integer(int)).toHexString() shouldBe "300302010$int".also {
                DER.decodeFromDer<UntaggedAsn1Integer>(it.hexToByteArray()) shouldBe UntaggedAsn1Integer(
                    int
                )
            }
        }
        "UntaggedElement" {
            DER.encodeToDer(UntaggedElement(int)).toHexString() shouldBe "300302010$int".also {
                DER.decodeFromDer<UntaggedElement>(it.hexToByteArray()) shouldBe UntaggedElement(
                    int
                )
            }
        }
        "ImplicitlyTaggedElement" {
            shouldThrow<SerializationException> {
                DER.encodeToDer(ImplicitlyTaggedElement(int))
            }
            shouldThrow<SerializationException> {
                DER.decodeFromDer<ImplicitlyTaggedElement>("300389010$int".hexToByteArray())
            }
        }

        "ValueClassImplicitlyTaggedElement" {
            DER.encodeToDer(ValueClassImplicitlyTaggedElement(int)).toHexString() shouldBe "300389010$int".also {
               val decoded=  DER.decodeFromDer<ValueClassImplicitlyTaggedElement>(it.hexToByteArray()) shouldBe ValueClassImplicitlyTaggedElement(
                    int
                )
                shouldThrow<SerializationException> {
                    DER.decodeFromDer<ValueClassImplicitlyTaggedElement>("300302010$int".hexToByteArray())
                }

                decoded.rawValue.tag.tagValue shouldBe 9uL
            }
        }
    }
}

@Serializable
data class UntaggedInt(val value: Int)

@Serializable
data class UntaggedAsn1Integer private constructor(val value: Asn1Integer) {
    constructor(value: Int) : this(Asn1Integer(value))
}

@Serializable
data class UntaggedElement private constructor(private val rawValue: Asn1Element) {
    //this is fine: default int tag, default int serializer, so everything just works, no manual parsing or custom serializer required
    constructor(value: Int) : this(DER.encodeToTlv(value))

    @Transient
    val value = DER.decodeFromTlv<Int>(rawValue)
}

@Serializable
data class ImplicitlyTaggedElement private constructor(@Asn1Tag(9u) private val rawValue: Asn1Element) {
    //The encoding path also works fine. default it serializer, no manual parsing or custom serializer required
    constructor(value: Int) : this(DER.encodeToTlv(value))

    @Transient
    //This is where deserialization fails, because Asn1Element does not have an int tag, but 0x89, so the default int serializer does not work due to a tag mismatch
    //The way around it would be to use a custom serializer or `decodeToInt` form the Asn1Element decoding functions

    //For this simple example this is not an issue, because there is such an int decoding function, but imagine we don't have int, but TbsCertificate, whose
    //raw ASN.1 representation is required (And yes, we want ASN.1 that round-trip deserializes and serializes to bytes, so we have structural guarantees; hence: raw bytes are not an option)
    val value = DER.decodeFromTlv<Int>(rawValue)
}

@Asn1Tag(9u)
@Serializable
@JvmInline
value class ImplicitlyTaggedInt(val value: Int)

@Serializable
data class ValueClassImplicitlyTaggedElement private constructor(val rawValue: Asn1Element) {
    constructor(value: Int) : this((DER.encodeToTlv(ImplicitlyTaggedInt(value))))

    @Transient
    val value: Int = DER.decodeFromTlv<ImplicitlyTaggedInt>(rawValue).value
}
