package at.asitplus.signum.indispensable.asn1

import at.asitplus.testballoon.checkAll
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.comparables.shouldBeGreaterThan
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.uLong

val TagSortingTest by testSuite {

    "Automated" - {
        val sortedClasses =
            listOf(TagClass.UNIVERSAL, TagClass.APPLICATION, TagClass.CONTEXT_SPECIFIC, TagClass.PRIVATE)
        checkAll(iterations = 1000, Arb.uLong()) - { a ->
            val tagA = Asn1Element.Tag(
                a,
                constructed = false,
                tagClass = TagClass.UNIVERSAL
            )
            val tagAAPP = Asn1Element.Tag(
                a,
                constructed = false,
                tagClass = TagClass.APPLICATION
            )
            val tagACTX = Asn1Element.Tag(
                a,
                constructed = false,
                tagClass = TagClass.CONTEXT_SPECIFIC
            )
            val tagAP = Asn1Element.Tag(
                a,
                constructed = false,
                tagClass = TagClass.PRIVATE
            )

            val tagAC = Asn1Element.Tag(
                a,
                constructed = true,
                tagClass = TagClass.UNIVERSAL
            )


            tagA.compareTo(tagAC) shouldBe 0

            tagA shouldBeLessThan tagAAPP
            tagAAPP shouldBeLessThan tagACTX
            tagACTX shouldBeLessThan tagAP

            tagAC shouldBeLessThan tagAAPP
            tagAC shouldBeLessThan tagACTX
            tagAC shouldBeLessThan tagAP


            checkAll(iterations = 1000, Arb.uLong()) { b ->
                val tagB = Asn1Element.Tag(
                    b,
                    constructed = false,
                    tagClass = TagClass.UNIVERSAL
                )

                if (a < b) {
                    tagA shouldBeLessThan tagB
                } else if (a > b) {
                    tagA shouldBeGreaterThan tagB
                }

                sortedClasses.forEachIndexed { i, left ->
                    sortedClasses.drop(i + 1).forEach { right ->
                        Asn1Element.Tag(a, constructed = false, tagClass = left) shouldBeLessThan
                                Asn1Element.Tag(b, constructed = false, tagClass = right)
                    }
                }
            }
        }
    }
}
