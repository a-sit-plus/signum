package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.decodeAsn1VarUInt
import at.asitplus.signum.indispensable.asn1.decodeAsn1VarULong
import at.asitplus.signum.indispensable.asn1.toAsn1VarInt
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.uInt
import io.kotest.property.arbitrary.uLong
import io.kotest.property.checkAll
import kotlin.random.Random

class UVarIntTest : FreeSpec({

    "UInts with trailing bytes" - {
        "manual" {
            byteArrayOf(65, 0, 0, 0).decodeAsn1VarUInt().first shouldBe 65u
        }
        "automated -" {
            checkAll(Arb.uInt()) { int ->
                (int.toAsn1VarInt().asList() + Random.nextBytes(8).asList()).decodeAsn1VarUInt().first shouldBe int

            }
        }
    }

    "ULongs with trailing bytes" - {
        "manual" {
            byteArrayOf(65, 0, 0, 0).decodeAsn1VarULong().first shouldBe 65uL
        }
        "automated -" {
            checkAll(Arb.uLong()) { long ->
                (long.toAsn1VarInt().asList() + Random.nextBytes(8).asList()).decodeAsn1VarULong().first shouldBe long

            }
        }
    }

})