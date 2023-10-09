import at.asitplus.crypto.datatypes.asn1.ObjectIdentifier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.Exhaustive
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.intArray
import io.kotest.property.arbitrary.positiveInt
import io.kotest.property.checkAll
import io.kotest.property.exhaustive.ints

@OptIn(ExperimentalUnsignedTypes::class)
class OidTest : FreeSpec({
    "OID test" - {

        "manual" {
            val oid = ObjectIdentifier("1.3.128.1.4.99991.9311.21.20")

            ObjectIdentifier.decodeFromTlv(oid.encodeToTlv()) shouldBe oid
        }
        checkAll(iterations = 10, Arb.intArray(Exhaustive.ints(2..2), Arb.positiveInt(10))) { firstTwo ->
            checkAll(iterations = 10, Arb.intArray(Arb.int(0..128), Arb.positiveInt(1000))) {
                val oid = ObjectIdentifier(*(firstTwo.map { it.toUInt() }.toUIntArray()),
                    *(it.map { it.toUInt() }.toUIntArray())
                )
                ObjectIdentifier.decodeFromTlv(oid.encodeToTlv()) shouldBe oid
            }
        }
    }
})