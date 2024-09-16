@file:OptIn(ExperimentalStdlibApi::class)

package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.*
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.uInt
import io.kotest.property.arbitrary.uLong
import io.kotest.property.checkAll
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERTaggedObject

class TagEncodingTest : FreeSpec({

    "fails" {
        val it = 2204309167L
        val bytes = (it).toTwosComplementByteArray()
        val fromBC = ASN1Integer(it).encoded
        val long = Long.decodeFromDerValue(bytes)
        val encoded = Asn1.Int(it).derEncoded
        encoded shouldBe fromBC
        long shouldBe it
    }

    "Manual" - {
        withData(207692171uL, 128uL, 36uL, 16088548868045964978uL, 15871772363588580035uL) {
            it.toAsn1VarInt().decodeAsn1VarULong().first shouldBe it
            val tag = Asn1Element.Tag(it, constructed = it % 2uL == 0uL)
            tag.tagValue shouldBe it

        }

    }
    "Automated" - {
        checkAll(iterations = 100000, Arb.uLong()) {
            it.toAsn1VarInt().decodeAsn1VarULong().first shouldBe it
            Asn1Element.Tag(it, constructed = it % 2uL == 0uL).tagValue shouldBe it
        }
    }
    "Against BC" - {
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


    "Ints" - {
        checkAll(iterations = 100000, Arb.uInt()) {
            it.toAsn1VarInt().apply {
                decodeAsn1VarULong().first.toUInt() shouldBe it
                decodeAsn1VarULong().first shouldBe it.toULong()
                decodeAsn1VarUInt().first shouldBe it
            }
        }
    }

})