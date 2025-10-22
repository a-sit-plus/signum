@file:OptIn(ExperimentalStdlibApi::class)

package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import io.kotest.assertions.withClue
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.positiveInt
import io.kotest.property.arbitrary.uInt
import io.kotest.property.arbitrary.uLong
import io.kotest.property.checkAll
import kotlinx.io.Buffer
import kotlinx.io.snapshot
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERTaggedObject
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

val TagEncodingTest by testSuite {

    "fails" {
        val it = 2204309167L
        val bytes = (it).toTwosComplementByteArray()
        val fromBC = ASN1Integer(it).encoded
        val long = Long.decodeFromAsn1ContentBytes(bytes)
        val encoded = Asn1.Int(it).derEncoded
        encoded shouldBe fromBC
        long shouldBe it
    }

    "length encoding" {
        checkAll(Arb.positiveInt()) {
           Buffer().apply { encodeLength(it.toLong()) }.snapshot().toByteArray() shouldBe it.encodeLength()
        }
    }

    "Manual" - {
        withData(207692171uL, 128uL, 36uL, 16088548868045964978uL, 15871772363588580035uL) {
            it.toAsn1VarInt().decodeAsn1VarULong().first shouldBe it
            val tag = Asn1Element.Tag(it, constructed = it % 2uL == 0uL)
            tag.tagValue shouldBe it

        }

    }
    "Automated" {
        checkAll(iterations = 100000, Arb.uLong()) {
            it.toAsn1VarInt().decodeAsn1VarULong().first shouldBe it
            Asn1Element.Tag(it, constructed = it % 2uL == 0uL).tagValue shouldBe it
        }
    }
    "Against BC" {
        checkAll(iterations = 1000000, Arb.int(min = 0)) {
            val tag = Asn1Element.Tag(it.toULong(), constructed = false)
            tag.tagValue shouldBe it.toULong()

            val bc = DERTaggedObject(true, it, ASN1Integer(1337))
            val own = Asn1.ExplicitlyTagged(it.toULong()) {
                +Asn1.Int(1337)
            }
            withClue(
                "Expected: ${bc.encoded.toHexString(HexFormat.UpperCase)}, actual: ${
                    own.derEncoded.toHexString(
                        HexFormat.UpperCase
                    )
                }"
            ) {
                own.derEncoded shouldBe bc.encoded
            }
        }
    }


    "Manual against BC" - {
        withData(207692171, 1337) {
            val tag = Asn1Element.Tag(it.toULong(), constructed = false)
            tag.tagValue shouldBe it.toULong()

            val bc = DERTaggedObject(true, it, ASN1Integer(1337))
            val own = Asn1.ExplicitlyTagged(it.toULong()) {
                +Asn1.Int(1337)
            }
            withClue(
                "Expected: ${bc.encoded.toHexString(HexFormat.UpperCase)}, actual: ${
                    own.derEncoded.toHexString(
                        HexFormat.UpperCase
                    )
                }"
            ) {
                own.derEncoded shouldBe bc.encoded
            }
        }
    }


    "Ints" {
        checkAll(iterations = 100000, Arb.uInt()) {
            it.toAsn1VarInt().apply {
                decodeAsn1VarULong().first.toUInt() shouldBe it
                decodeAsn1VarULong().first shouldBe it.toULong()
                decodeAsn1VarUInt().first shouldBe it
            }
        }
    }

}
