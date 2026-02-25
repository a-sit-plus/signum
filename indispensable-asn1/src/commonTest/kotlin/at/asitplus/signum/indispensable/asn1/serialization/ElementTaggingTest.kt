package io.kotest.property.at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.serialization.Asn1Tag
import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.signum.indispensable.asn1.serialization.decodeFromDer
import at.asitplus.signum.indispensable.asn1.serialization.decodeFromTlv
import at.asitplus.signum.indispensable.asn1.serialization.encodeToDer
import at.asitplus.signum.indispensable.asn1.serialization.encodeToTlv
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient


val TaggedTest by testSuite {
    withData(0,2,3,4,5,6,7,8,9) { int ->
        DER.encodeToDer(UntaggedInt(int) ).toHexString() shouldBe "300302010$int".also { DER.decodeFromDer<UntaggedInt>(it.hexToByteArray()) shouldBe UntaggedInt(int) }
        DER.encodeToDer(UntaggedAsn1Integer(int) ).toHexString() shouldBe "300302010$int".also { DER.decodeFromDer<UntaggedAsn1Integer>(it.hexToByteArray()) shouldBe UntaggedAsn1Integer(int) }
        DER.encodeToDer(UntaggedElement(int) ).toHexString() shouldBe "300302010$int".also { DER.decodeFromDer<UntaggedElement>(it.hexToByteArray()) shouldBe UntaggedElement(int) }
        DER.encodeToDer(TaggedElement(int) ).toHexString() shouldBe "300389010$int".also { DER.decodeFromDer<TaggedElement>(it.hexToByteArray()) shouldBe TaggedElement(int) }
    }
}

@Serializable
data class UntaggedInt(val value: Int)

@Serializable
data class UntaggedAsn1Integer private constructor (val value: Asn1Integer) {
    constructor(value: Int) : this(Asn1Integer(value))
}

@Serializable
data class UntaggedElement private constructor(private val value_: Asn1Element) {
    constructor(value: Int) : this(DER.encodeToTlv(value))
    @Transient val value = DER.decodeFromTlv<Int>(value_)
}
@Serializable
data class TaggedElement private constructor(@Asn1Tag(0x9u) private val value_: Asn1Element) {
    constructor(value: Int) : this(DER.encodeToTlv(value))

    @Transient
    val value = DER.decodeFromTlv<Int>(value_)
}