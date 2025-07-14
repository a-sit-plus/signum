package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import io.kotest.assertions.throwables.shouldThrow
import at.asitplus.test.FreeSpec
import io.kotest.property.Arb
import io.kotest.property.arbitrary.uLong
import io.kotest.property.checkAll

class TagAssertionTest : FreeSpec({
    "Automated" - {
        checkAll(iterations = 100000, Arb.uLong(max = ULong.MAX_VALUE - 2uL)) {
            var seq = (Asn1.Sequence { } withImplicitTag it).asStructure()
            seq.assertTag(it)
            shouldThrow<Asn1TagMismatchException> {
                seq.assertTag(it + 1uL)
            }
        }
    }
})