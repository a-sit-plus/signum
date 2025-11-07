package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.testballoon.checkAll
import at.asitplus.testballoon.minus
import io.kotest.assertions.throwables.shouldThrow
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.property.Arb
import io.kotest.property.arbitrary.uLong

val TagAssertionTest by testSuite {
    "Automated" - {
        checkAll(iterations = 100000, Arb.uLong(max = ULong.MAX_VALUE - 2uL)) {
            var seq = (Asn1.Sequence { } withImplicitTag it).asStructure()
            seq.assertTag(it)
            shouldThrow<Asn1TagMismatchException> {
                seq.assertTag(it + 1uL)
            }
        }
    }
}
