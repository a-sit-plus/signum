package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import io.kotest.assertions.throwables.shouldThrow
import at.asitplus.testballoon.matrix.*
import io.kotest.property.Arb
import io.kotest.property.arbitrary.uLong

val TagAssertionTest by matrixSuite {
    compact("Automated") - {
        property(Arb.uLong(max = ULong.MAX_VALUE - 2uL), iterations = 100000) test {
            var seq = (Asn1.Sequence { } withImplicitTag it).asStructure()
            seq.assertTag(it)
            shouldThrow<Asn1TagMismatchException> {
                seq.assertTag(it + 1uL)
            }
        }
    }
}
