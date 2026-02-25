package io.kotest.property.at.asitplus.signum.indispensable.asn1.serialization

import Asn1Backed
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
            DER.encodeToDer(ImplicitlyTaggedElement(int)).toHexString() shouldBe "300389010$int".also {
                DER.decodeFromDer<ImplicitlyTaggedElement>(it.hexToByteArray()) shouldBe ImplicitlyTaggedElement(
                    int
                )
            }
        }

        "Asn1BackedImplicitlyTagged" {
            DER.encodeToDer(Asn1BackedImplicitlyTagged(int)).toHexString() shouldBe "300389010$int".also {
                DER.decodeFromDer<Asn1BackedImplicitlyTagged>(it.hexToByteArray()).also { decoded ->
                    decoded.rawValue.asn1Element!!.tag.tagValue shouldBe 9uL
                } shouldBe Asn1BackedImplicitlyTagged(
                    int
                )
            }

            withClue("missing implicit tag, default int tag") {
                //As you can see, this throws, because the int was not implicitly tagged. so ALL the validations are done
                //as if there were no Asn1Backed in place
                shouldThrow<SerializationException> {
                    DER.decodeFromDer<Asn1BackedImplicitlyTagged>("300302010$int".hexToByteArray())
                }
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
data class UntaggedElement private constructor(private val value_: Asn1Element) {
    //this is fine: default int tag, default int serializer, so everything just works, no manual parsing or custom serializer required
    constructor(value: Int) : this(DER.encodeToTlv(value))

    @Transient
    val value = DER.decodeFromTlv<Int>(value_)
}

@Serializable
data class ImplicitlyTaggedElement private constructor(@Asn1Tag(9u) private val _value: Asn1Element) {
    //The encoding path also works fine. default it serializer, no manual parsing or custom serializer required
    constructor(value: Int) : this(DER.encodeToTlv(value))

    @Transient
    //This is where deserialization fails, because Asn1Element does not have an int tag, but 0x89, so the default int serializer does not work due to a tag mismatch
    //The way around it would be to use a custom serializer or `decodeToInt` form the Asn1Element decoding functions

    //For this simple example this is not an issue, because there is such an int decoding function, but imagine we don't have int, but TbsCertificate, whose
    //raw ASN.1 representation is required (And yes, we want ASN.1 that round-trip deserializes and serializes to bytes, so we have structural guarantees; hence: raw bytes are not an option)
    val value = DER.decodeFromTlv<Int>(_value)
}


@Serializable
data class Asn1BackedImplicitlyTagged private constructor(@Asn1Tag(9u) val rawValue: Asn1Backed<Int>) {
    //The encoding path also works fine. default it serializer, no manual parsing or custom serializer required

    //The deserialization codepath performs all the exact same checks as with a regular plain int and gives the ras ASN.1 element in addtion to the
    //decoded value. So if decoding fails we get an exception. if it works, we have the guarantee that the value is structurally a correct representation of the underlying type

    // at the same time the asn.1 bytes are not touched, because TLV will be preserved byte for byte when re-encoding and TLV knnows nothing about booleans, ints, etc.

    //moreover: Asn1Backed is completely invisible to other serializazion formats, so I can even debug this to JSON
    constructor(value: Int) : this(Asn1Backed(value))

    @Transient
    //This also works perfectly fine and we can encode and decode as often as we want: If an Asn1Backed's asn1Element is present, it can just be re-emitted as-is, to keep byte-level faults that don't impact the TLV tree (like sorting issues, or illegal characters inside a string, etc.)
    val value = rawValue.value
}