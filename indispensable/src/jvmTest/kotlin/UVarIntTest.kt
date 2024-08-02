import at.asitplus.signum.indispensable.misc.UVarInt
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.uInt
import io.kotest.property.checkAll

class UVarIntTest : FreeSpec({

    "Conversion and Equality" - {
        checkAll(
            iterations = 1024,
            Arb.uInt()
        ) {
            UVarInt(it).toULong().toUInt() shouldBe it
            UVarInt.fromByteArray(UVarInt(it).encodeToByteArray()).toULong().toUInt() shouldBe it
        }
    }
})