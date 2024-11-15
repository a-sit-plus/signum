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
            Arb.byteArray(length = Arb.int(0, 10), content = Arb.byte())
        ) { bytes ->
            val bytesSigned1 = CoseSigned<ByteArray>(
                protectedHeader = ByteStringWrapper<CoseHeader>(CoseHeader()),
                unprotectedHeader = null,
                payload = bytes,
                rawSignature = bytes
            )
            val bytesSigned2 = CoseSigned<ByteArray>(
                protectedHeader = ByteStringWrapper<CoseHeader>(CoseHeader()),
                unprotectedHeader = null,
                payload = bytes,
                rawSignature = bytes
            )

            bytesSigned1 shouldBe bytesSigned1
            bytesSigned2 shouldBe bytesSigned1
            bytesSigned1.hashCode() shouldBe bytesSigned1.hashCode()
            bytesSigned1.hashCode() shouldBe bytesSigned2.hashCode()

            val reversed = bytes.reversedArray().let { it + it + 1 + 3 + 5 }
            val reversedSigned1 = CoseSigned<ByteArray>(
                protectedHeader = ByteStringWrapper<CoseHeader>(CoseHeader()),
                unprotectedHeader = null,
                payload = reversed,
                rawSignature = reversed
            )
            val reversedSigned2 = CoseSigned<ByteArray>(
                protectedHeader = ByteStringWrapper<CoseHeader>(CoseHeader()),
                unprotectedHeader = null,
                payload = reversed,
                rawSignature = reversed
            )

            reversedSigned2 shouldBe reversedSigned2
            reversedSigned2 shouldBe reversedSigned1

            reversedSigned1.hashCode() shouldBe reversedSigned1.hashCode()
            reversedSigned1.hashCode() shouldBe reversedSigned2.hashCode()

            bytesSigned1 shouldNotBe reversedSigned1
            bytesSigned1 shouldNotBe reversedSigned2

            bytesSigned1.hashCode() shouldNotBe reversedSigned1.hashCode()
            bytesSigned1.hashCode() shouldNotBe reversedSigned2.hashCode()

            reversedSigned1 shouldNotBe bytesSigned1
            reversedSigned1 shouldNotBe bytesSigned2

            reversedSigned1.hashCode() shouldNotBe bytesSigned1.hashCode()
            reversedSigned1.hashCode() shouldNotBe bytesSigned2.hashCode()
        }

    }
})
