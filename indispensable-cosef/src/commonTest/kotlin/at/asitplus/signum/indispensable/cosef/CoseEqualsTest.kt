package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int
import io.kotest.property.checkAll

class CoseEqualsTest : FreeSpec({
    "Test Equals" - {
        checkAll(
            Arb.byteArray(
                length = Arb.int(0, 10),
                content = Arb.byte()
            )
        ) { s1 ->
            val signed1 = CoseSigned(
                protectedHeader = ByteStringWrapper<CoseHeader>(CoseHeader()),
                unprotectedHeader = null,
                payload = s1,
                rawSignature = s1
            )
            val signed11 = CoseSigned(
                protectedHeader = ByteStringWrapper<CoseHeader>(CoseHeader()),
                unprotectedHeader = null,
                payload = s1,
                rawSignature = s1
            )

            signed1 shouldBe signed1
            signed11 shouldBe signed1
            signed1.hashCode() shouldBe signed1.hashCode()
            signed1.hashCode() shouldBe signed11.hashCode()

            val s2 = s1.reversedArray().let { it + it + 1 + 3 + 5 }
            val signed2 = CoseSigned(
                protectedHeader = ByteStringWrapper<CoseHeader>(CoseHeader()),
                unprotectedHeader = null,
                payload = s2,
                rawSignature = s2
            )
            val signed22 = CoseSigned(
                protectedHeader = ByteStringWrapper<CoseHeader>(CoseHeader()),
                unprotectedHeader = null,
                payload = s2,
                rawSignature = s2
            )

            signed22 shouldBe signed22
            signed22 shouldBe signed2

            signed2.hashCode() shouldBe signed2.hashCode()
            signed2.hashCode() shouldBe signed22.hashCode()

            signed1 shouldNotBe signed2
            signed1 shouldNotBe signed22

            signed1.hashCode() shouldNotBe signed2.hashCode()
            signed1.hashCode() shouldNotBe signed22.hashCode()

            signed2 shouldNotBe signed1
            signed2 shouldNotBe signed11

            signed2.hashCode() shouldNotBe signed1.hashCode()
            signed2.hashCode() shouldNotBe signed11.hashCode()
        }

    }
})