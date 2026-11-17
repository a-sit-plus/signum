package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.decodeAsn1VarUInt
import at.asitplus.signum.indispensable.asn1.encoding.decodeAsn1VarULong
import at.asitplus.signum.indispensable.asn1.encoding.decodeToAsn1Integer
import at.asitplus.signum.indispensable.asn1.encoding.decodeToAsn1IntegerOrNull
import at.asitplus.signum.indispensable.asn1.encoding.toAsn1VarInt
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope

@OptIn(ExperimentalStdlibApi::class)
val SpecificRegressionTests by matrixSuite {
    "Illegal length encoding" {
        shouldThrow<Asn1Exception> {
            // length < 128 encoded as long form
            Asn1Element.parseFromDerHexString("01811d2b378be969f614283650e8ca3b07eba2289841239513e24fd230e5a538")
        }
        shouldThrow<Asn1Exception> {
            // length > 128 not encoded in the minimum number of bytes
            Asn1Element.parseFromDerHexString("01820080" + "00".repeat(0x80))
        }
    }

    "Illegal long-form tag number encoding" {
        shouldThrow<Asn1Exception> { Asn1Element.parseFromDerHexString("BF0003020105") }
        shouldThrow<Asn1Exception> { Asn1Element.parseFromDerHexString("9F1E0105") }
        shouldThrow<Asn1Exception> { Asn1Element.parseFromDerHexString("9F801F0105") }
        shouldThrow<Asn1Exception> { Asn1Element.parseFromDerHexString("BF82808080808080808000" + "03020105") }

        listOf(
            "9F1F0105",
            "9F" + ULong.MAX_VALUE.toAsn1VarInt().toHexString() + "0105",
        ).forEach { hex ->
            Asn1Element.parseFromDerHexString(hex.uppercase()).derEncoded.toHexString() shouldBe hex.lowercase()
        }
    }

    "Varint decoding rejects overflow and truncation" {
        shouldThrow<IllegalArgumentException> { "82808080808080808000".hexToByteArray().decodeAsn1VarULong() }
        shouldThrow<IllegalArgumentException> { "9080808000".hexToByteArray().decodeAsn1VarUInt() }
        shouldThrow<IllegalArgumentException> { "8180".hexToByteArray().decodeAsn1VarULong() }

        ULong.MAX_VALUE.toAsn1VarInt().decodeAsn1VarULong().first shouldBe ULong.MAX_VALUE
        UInt.MAX_VALUE.toULong().toAsn1VarInt().decodeAsn1VarUInt().first shouldBe UInt.MAX_VALUE
    }

    "decodeToAsn1IntegerOrNull honours assertTag" {
        val implicitTag = Asn1Element.Tag(1u, constructed = false, tagClass = TagClass.CONTEXT_SPECIFIC)
        val implicitlyTagged = Asn1Primitive(implicitTag, byteArrayOf(5))
        implicitlyTagged.decodeToAsn1IntegerOrNull(implicitTag) shouldBe implicitlyTagged.decodeToAsn1Integer(implicitTag)
        Asn1Primitive(Asn1Element.Tag.INT, byteArrayOf(5)).decodeToAsn1IntegerOrNull(implicitTag) shouldBe null
    }
}
