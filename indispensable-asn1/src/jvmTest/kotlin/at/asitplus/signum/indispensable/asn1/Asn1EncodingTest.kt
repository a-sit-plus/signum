package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Bool
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Null
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.OctetString
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.OctetStringEncapsulating
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.PrintableString
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.UtcTime
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Utf8String
import at.asitplus.signum.indispensable.asn1.encoding.decodeToBoolean
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1UtcTimePrimitive
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.testSuite

import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.boolean
import io.kotest.property.checkAll
import kotlin.time.Clock
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

val Asn1EncodingTest by testSuite() {

    "Boolean" {
        checkAll(Arb.boolean()) {
            val seq = Asn1.Sequence { +Asn1.Bool(it) }
            val decoded = (seq.iterator().next() as Asn1Primitive).decodeToBoolean()
            decoded shouldBe it
        }
    }
    "Manual" - {
        withData(
            "A3 82 03 8F 30 82 03 8B 30 1F 06 03 55 1D 23 04 18 30 16 80 14 0A BC 08 29 17 8C A5 39 6D 7A 0E CE 33 C7 2E B3 ED FB C3 7A 30 1D 06 03 55 1D 0E 04 16 04 14 C7 07 27 78 85 F2 9D 33 C9 4C 5E 56 7D 5C D6 8E 72 67 EB DE 30 25 06 03 55 1D 11 04 1E 30 1C 82 0A 67 69 74 68 75 62 2E 63 6F 6D 82 0E 77 77 77 2E 67 69 74 68 75 62 2E 63 6F 6D 30 0E 06 03 55 1D 0F 01 01 FF 04 04 03 02 07 80 30 1D 06 03 55 1D 25 04 16 30 14 06 08 2B 06 01 05 05 07 03 01 06 08 2B 06 01 05 05 07 03 02 30 81 9B 06 03 55 1D 1F 04 81 93 30 81 90 30 46 A0 44 A0 42 86 40 68 74 74 70 3A 2F 2F 63 72 6C 33 2E 64 69 67 69 63 65 72 74 2E 63 6F 6D 2F 44 69 67 69 43 65 72 74 54 4C 53 48 79 62 72 69 64 45 43 43 53 48 41 33 38 34 32 30 32 30 43 41 31 2D 31 2E 63 72 6C 30 46 A0 44 A0 42 86 40 68 74 74 70 3A 2F 2F 63 72 6C 34 2E 64 69 67 69 63 65 72 74 2E 63 6F 6D 2F 44 69 67 69 43 65 72 74 54 4C 53 48 79 62 72 69 64 45 43 43 53 48 41 33 38 34 32 30 32 30 43 41 31 2D 31 2E 63 72 6C 30 3E 06 03 55 1D 20 04 37 30 35 30 33 06 06 67 81 0C 01 02 02 30 29 30 27 06 08 2B 06 01 05 05 07 02 01 16 1B 68 74 74 70 3A 2F 2F 77 77 77 2E 64 69 67 69 63 65 72 74 2E 63 6F 6D 2F 43 50 53 30 81 85 06 08 2B 06 01 05 05 07 01 01 04 79 30 77 30 24 06 08 2B 06 01 05 05 07 30 01 86 18 68 74 74 70 3A 2F 2F 6F 63 73 70 2E 64 69 67 69 63 65 72 74 2E 63 6F 6D 30 4F 06 08 2B 06 01 05 05 07 30 02 86 43 68 74 74 70 3A 2F 2F 63 61 63 65 72 74 73 2E 64 69 67 69 63 65 72 74 2E 63 6F 6D 2F 44 69 67 69 43 65 72 74 54 4C 53 48 79 62 72 69 64 45 43 43 53 48 41 33 38 34 32 30 32 30 43 41 31 2D 31 2E 63 72 74 30 09 06 03 55 1D 13 04 02 30 00 30 82 01 80 06 0A 2B 06 01 04 01 D6 79 02 04 02 04 82 01 70 04 82 01 6C 01 6A 00 77 00 EE CD D0 64 D5 DB 1A CE C5 5C B7 9D B4 CD 13 A2 32 87 46 7C BC EC DE C3 51 48 59 46 71 1F B5 9B 00 00 01 86 50 DD 1B FA 00 00 04 03 00 48 30 46 02 21 00 E4 16 AE D3 E2 2C BA 82 9F A9 79 F2 4B C6 94 52 ED 4D E0 87 CC 50 CA 69 B1 B4 8F 05 77 3A 94 EB 02 21 00 B5 9F C3 F9 CB 0F AD D0 60 F2 30 1B 71 05 72 12 0D BD 65 1F 07 A9 9C 53 4B 76 95 12 04 A6 BF 2E 00 76 00 48 B0 E3 6B DA A6 47 34 0F E5 6A 02 FA 9D 30 EB 1C 52 01 CB 56 DD 2C 81 D9 BB BF AB 39 D8 84 73 00 00 01 86 50 DD 1C 2B 00 00 04 03 00 47 30 45 02 20 1E 3C 60 32 7E 20 51 F5 D6 E1 AF 7D 4D F5 97 C4 48 2E 46 57 6B 86 05 37 32 4F 25 04 36 B1 F7 B7 02 21 00 FC 09 7E C0 7C 03 83 26 36 BD A7 5B EB 1D 13 59 F6 62 20 8E 6D 6F B7 0D 31 EB DB F5 11 EE 5B D4 00 77 00 3B 53 77 75 3E 2D B9 80 4E 8B 30 5B 06 FE 40 3B 67 D8 4F C3 F4 C7 BD 00 0D 2D 72 6F E1 FA D4 17 00 00 01 86 50 DD 1C 3A 00 00 04 03 00 48 30 46 02 21 00 CC E0 6B F4 E6 74 FB A3 92 67 21 53 8B 2C 0D EB 83 F2 B0 DD 05 2D E2 D1 C8 BE 63 98 4B 18 AC 36 02 21 00 EE D2 3B 60 5A 23 08 29 4E 82 33 47 4A 72 A5 16 2E 46 85 13 6D DC DA 25 80 85 80 07 AA B1 51 47",
            "30 82 05 6A 30 82 04 F1 A0 03 02 01 02 02 10 0C D0 A8 BE C6 32 CF E6 45 EC A0 A9 B0 84 FB 1C 30 0A 06 08 2A 86 48 CE 3D 04 03 03 30 56 31 0B 30 09 06 03 55 04 06 13 02 55 53 31 15 30 13 06 03 55 04 0A 13 0C 44 69 67 69 43 65 72 74 20 49 6E 63 31 30 30 2E 06 03 55 04 03 13 27 44 69 67 69 43 65 72 74 20 54 4C 53 20 48 79 62 72 69 64 20 45 43 43 20 53 48 41 33 38 34 20 32 30 32 30 20 43 41 31 30 1E 17 0D 32 33 30 32 31 34 30 30 30 30 30 30 5A 17 0D 32 34 30 33 31 34 32 33 35 39 35 39 5A 30 66 31 0B 30 09 06 03 55 04 06 13 02 55 53 31 13 30 11 06 03 55 04 08 13 0A 43 61 6C 69 66 6F 72 6E 69 61 31 16 30 14 06 03 55 04 07 13 0D 53 61 6E 20 46 72 61 6E 63 69 73 63 6F 31 15 30 13 06 03 55 04 0A 13 0C 47 69 74 48 75 62 2C 20 49 6E 63 2E 31 13 30 11 06 03 55 04 03 13 0A 67 69 74 68 75 62 2E 63 6F 6D 30 59 30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07 03 42 00 04 A3 A4 03 46 03 DF 46 51 56 CB C9 39 AB 22 CD E7 6C 59 96 7A 93 A0 FB B9 40 1C 90 32 88 36 C6 09 76 9C 50 F5 55 F7 76 5E 68 20 9C EE 22 ED 83 0C 15 30 10 41 44 5E 32 AC 90 A1 D5 AA F2 E5 43 B3 A3 82 03 8F 30 82 03 8B 30 1F 06 03 55 1D 23 04 18 30 16 80 14 0A BC 08 29 17 8C A5 39 6D 7A 0E CE 33 C7 2E B3 ED FB C3 7A 30 1D 06 03 55 1D 0E 04 16 04 14 C7 07 27 78 85 F2 9D 33 C9 4C 5E 56 7D 5C D6 8E 72 67 EB DE 30 25 06 03 55 1D 11 04 1E 30 1C 82 0A 67 69 74 68 75 62 2E 63 6F 6D 82 0E 77 77 77 2E 67 69 74 68 75 62 2E 63 6F 6D 30 0E 06 03 55 1D 0F 01 01 FF 04 04 03 02 07 80 30 1D 06 03 55 1D 25 04 16 30 14 06 08 2B 06 01 05 05 07 03 01 06 08 2B 06 01 05 05 07 03 02 30 81 9B 06 03 55 1D 1F 04 81 93 30 81 90 30 46 A0 44 A0 42 86 40 68 74 74 70 3A 2F 2F 63 72 6C 33 2E 64 69 67 69 63 65 72 74 2E 63 6F 6D 2F 44 69 67 69 43 65 72 74 54 4C 53 48 79 62 72 69 64 45 43 43 53 48 41 33 38 34 32 30 32 30 43 41 31 2D 31 2E 63 72 6C 30 46 A0 44 A0 42 86 40 68 74 74 70 3A 2F 2F 63 72 6C 34 2E 64 69 67 69 63 65 72 74 2E 63 6F 6D 2F 44 69 67 69 43 65 72 74 54 4C 53 48 79 62 72 69 64 45 43 43 53 48 41 33 38 34 32 30 32 30 43 41 31 2D 31 2E 63 72 6C 30 3E 06 03 55 1D 20 04 37 30 35 30 33 06 06 67 81 0C 01 02 02 30 29 30 27 06 08 2B 06 01 05 05 07 02 01 16 1B 68 74 74 70 3A 2F 2F 77 77 77 2E 64 69 67 69 63 65 72 74 2E 63 6F 6D 2F 43 50 53 30 81 85 06 08 2B 06 01 05 05 07 01 01 04 79 30 77 30 24 06 08 2B 06 01 05 05 07 30 01 86 18 68 74 74 70 3A 2F 2F 6F 63 73 70 2E 64 69 67 69 63 65 72 74 2E 63 6F 6D 30 4F 06 08 2B 06 01 05 05 07 30 02 86 43 68 74 74 70 3A 2F 2F 63 61 63 65 72 74 73 2E 64 69 67 69 63 65 72 74 2E 63 6F 6D 2F 44 69 67 69 43 65 72 74 54 4C 53 48 79 62 72 69 64 45 43 43 53 48 41 33 38 34 32 30 32 30 43 41 31 2D 31 2E 63 72 74 30 09 06 03 55 1D 13 04 02 30 00 30 82 01 80 06 0A 2B 06 01 04 01 D6 79 02 04 02 04 82 01 70 04 82 01 6C 01 6A 00 77 00 EE CD D0 64 D5 DB 1A CE C5 5C B7 9D B4 CD 13 A2 32 87 46 7C BC EC DE C3 51 48 59 46 71 1F B5 9B 00 00 01 86 50 DD 1B FA 00 00 04 03 00 48 30 46 02 21 00 E4 16 AE D3 E2 2C BA 82 9F A9 79 F2 4B C6 94 52 ED 4D E0 87 CC 50 CA 69 B1 B4 8F 05 77 3A 94 EB 02 21 00 B5 9F C3 F9 CB 0F AD D0 60 F2 30 1B 71 05 72 12 0D BD 65 1F 07 A9 9C 53 4B 76 95 12 04 A6 BF 2E 00 76 00 48 B0 E3 6B DA A6 47 34 0F E5 6A 02 FA 9D 30 EB 1C 52 01 CB 56 DD 2C 81 D9 BB BF AB 39 D8 84 73 00 00 01 86 50 DD 1C 2B 00 00 04 03 00 47 30 45 02 20 1E 3C 60 32 7E 20 51 F5 D6 E1 AF 7D 4D F5 97 C4 48 2E 46 57 6B 86 05 37 32 4F 25 04 36 B1 F7 B7 02 21 00 FC 09 7E C0 7C 03 83 26 36 BD A7 5B EB 1D 13 59 F6 62 20 8E 6D 6F B7 0D 31 EB DB F5 11 EE 5B D4 00 77 00 3B 53 77 75 3E 2D B9 80 4E 8B 30 5B 06 FE 40 3B 67 D8 4F C3 F4 C7 BD 00 0D 2D 72 6F E1 FA D4 17 00 00 01 86 50 DD 1C 3A 00 00 04 03 00 48 30 46 02 21 00 CC E0 6B F4 E6 74 FB A3 92 67 21 53 8B 2C 0D EB 83 F2 B0 DD 05 2D E2 D1 C8 BE 63 98 4B 18 AC 36 02 21 00 EE D2 3B 60 5A 23 08 29 4E 82 33 47 4A 72 A5 16 2E 46 85 13 6D DC DA 25 80 85 80 07 AA B1 51 47 30 0A 06 08 2A 86 48 CE 3D 04 03 03 03 67 00 30 64 02 30 04 DC 0D D4 DE 34 99 0A 9C 1F A8 E1 C1 76 5C 62 F4 04 A0 29 35 3E C2 0D 2A C3 71 6A B5 F4 37 D4 EC 0B 60 57 71 87 43 25 36 4F C7 C2 48 D1 49 68 02 30 56 D0 BC C9 17 10 FB CD BE FE 2D DF 42 BA C6 DA 46 DB AA A6 67 EE 8E 88 84 81 20 85 CC 96 35 A7 B2 26 11 D6 0C 99 9D 3C C8 83 70 10 4B 0E 15 9B",
            "30 1D 06 03 55 1D 0E 04 16 04 14 EB 92 86 2F 31 C3 DB 96 A3 49 FF CB A5 15 64 23 14 B3 D2 3D"
        ) {

            Asn1Element.Companion.parseFromDerHexString(it).toDerHexString() shouldBe it.replace(" ", "")
        }
    }


    val bitSet = BitSet.fromBitString("011011100101110111")
    "Bit String" {
        val fromBitSet = Asn1BitString(bitSet)
        fromBitSet.encodeToTlv().toDerHexString() shouldBe "0304066E5DC0"
        fromBitSet.toBitSet().toBitString() shouldBe "011011100101110111"
        fromBitSet.toBitSet() shouldBe bitSet

        Asn1BitString.decodeFromTlv(Asn1.Sequence { +Asn1.BitString(bitSet) }.children.first() as Asn1Primitive)
            .toBitSet() shouldBe bitSet
    }

    "OCTET STRING Test" {
        val seq = Asn1.Sequence {
            +OctetStringEncapsulating {
                +Asn1.Sequence { +Asn1.Utf8String("foo") }
                +Asn1.Set { +Asn1.Utf8String("bar") }
                +PrintableString("a")
            }
            OctetString(byteArrayOf(17))

            +OctetString(
                Asn1.Set {
                    +Asn1.Int(99)
                    +OctetString(byteArrayOf(1, 2, 3))
                    +OctetStringEncapsulating {
                        +Asn1EncapsulatingOctetString(
                            listOf(
                                Asn1PrimitiveOctetString(
                                    byteArrayOf(
                                        7,
                                        6,
                                        3,
                                    )
                                )
                            )
                        )
                    }
                }.derEncoded
            )
            +ExplicitlyTagged(9u) { +Clock.System.now().encodeToAsn1UtcTimePrimitive() }
            +OctetString(byteArrayOf(17, -43, 23, -12, 8, 65, 90))
            +Bool(false)
            +Bool(true)
        }
        val parsed = Asn1Element.parse(seq.derEncoded)
        parsed.shouldNotBeNull()
    }

    "Old and new encoder produce the same bytes" {

        val instant = Clock.System.now()

        val sequence = Asn1.Sequence {
            +ExplicitlyTagged(1u) { +Asn1Primitive(BERTags.BOOLEAN, byteArrayOf(0x00)) }
            +Asn1.Set {
                +Asn1.Sequence {
                    +Asn1.SetOf {
                        +PrintableString("World")
                        +PrintableString("Hello")
                    }
                    +Asn1.Set {
                        +PrintableString("World")
                        +PrintableString("Hello")
                        +Utf8String("!!!")
                    }

                }
            }
            +Null()

            +ObjectIdentifier("1.2.603.624.97")

            +Utf8String("Foo")
            +PrintableString("Bar")

            +Asn1.Set {
                +Asn1.Int(3)
                +Asn1.Int(-65789876543L)
                +Bool(false)
                +Bool(true)
            }
            +Asn1.Sequence {
                +Null()
                +Asn1String.Numeric("12345")
                +UtcTime(instant)
            }
        }
        Asn1Element.parse(sequence.derEncoded).derEncoded shouldBe sequence.derEncoded
    }
}
