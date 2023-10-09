import at.asitplus.crypto.datatypes.asn1.ObjectIdentifier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.intArray
import io.kotest.property.arbitrary.positiveInt
import io.kotest.property.checkAll

@OptIn(ExperimentalUnsignedTypes::class)
class OidTest : FreeSpec({
    "OID test" - {

        "manual" {
            val oid = ObjectIdentifier("1.3.311.128.1.4.99991.9311.21.20")

            ObjectIdentifier.decodeFromTlv(oid.encodeToTlv()) shouldBe oid
        }

        checkAll(iterations = 15, Arb.positiveInt(39)) { second ->
            checkAll(iterations = 1000, Arb.intArray(Arb.int(0..128), Arb.positiveInt(Int.MAX_VALUE))) {
                listOf(1, 2).forEach { first ->
                    val oid = ObjectIdentifier(
                        first.toUInt(),
                        second.toUInt(),
                        *(it.map { it.toUInt() }.toUIntArray())
                    )

                    val parsed = ObjectIdentifier.decodeFromTlv(oid.encodeToTlv())
                    if (parsed != oid) println("is:     $oid\nparsed: $parsed")
                    parsed shouldBe oid
                }
            }
        }
    }
})