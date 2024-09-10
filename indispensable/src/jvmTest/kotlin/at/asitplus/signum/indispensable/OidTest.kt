package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.intArray
import io.kotest.property.arbitrary.positiveInt
import io.kotest.property.checkAll
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERTaggedObject

class OidTest : FreeSpec({
    "OID test" - {

        "manual" {
            val oid = ObjectIdentifier("1.3.311.128.1.4.99991.9311.21.20")
            val oid1 = ObjectIdentifier("1.3.311.128.1.4.99991.9311.21.20")
            val oid2 = ObjectIdentifier("1.3.312.128.1.4.99991.9311.21.20")

            ObjectIdentifier.decodeFromTlv(oid.encodeToTlv()) shouldBe oid
            oid shouldBe oid1
            oid shouldNotBe oid2
            oid.hashCode() shouldBe oid1.hashCode()
            oid.hashCode() shouldNotBe oid2.hashCode()
        }

        "Automated" - {
            checkAll(iterations = 15, Arb.positiveInt(39)) { second ->
                checkAll(iterations = 5000, Arb.intArray(Arb.int(0..128), Arb.positiveInt(Int.MAX_VALUE))) {
                    listOf(1, 2).forEach { first ->
                        val oid = ObjectIdentifier(
                            first.toUInt(),
                            second.toUInt(),
                            *(it.map { it.toUInt() }.toUIntArray())
                        )

                        val stringRepresentation =
                            "$first.$second" + if (it.isEmpty()) "" else ("." + it.joinToString("."))

                        val second1 = if (second > 1) second - 1 else second + 1

                        val oid1 = ObjectIdentifier(
                            first.toUInt(),
                            second1.toUInt(),
                            *(it.map { it.toUInt() }.toUIntArray())
                        )
                        val parsed = ObjectIdentifier.decodeFromTlv(oid.encodeToTlv())
                        val fromBC = ASN1ObjectIdentifier(stringRepresentation)

                        val bcEncoded = fromBC.encoded
                        val ownEncoded = oid.encodeToDer()

                        @OptIn(ExperimentalStdlibApi::class)
                        withClue(
                            "Expected: ${bcEncoded.toHexString(HexFormat.UpperCase)}\nActual: ${
                                ownEncoded.toHexString(
                                    HexFormat.UpperCase
                                )
                            }"
                        ) {
                            bcEncoded shouldBe ownEncoded
                        }
                        parsed shouldBe oid
                        parsed.hashCode() shouldBe oid.hashCode()
                        parsed shouldNotBe oid1
                        parsed.hashCode() shouldNotBe oid1.hashCode()
                    }
                }
            }
        }
    }
})