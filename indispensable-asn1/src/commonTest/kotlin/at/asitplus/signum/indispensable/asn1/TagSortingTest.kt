package at.asitplus.signum.indispensable.asn1

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.comparables.shouldBeGreaterThan
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.uLong
import io.kotest.property.checkAll

val TagSortingTest by testSuite {

    "Automated" {
        val sortedClasses =
            listOf(TagClass.UNIVERSAL, TagClass.APPLICATION, TagClass.CONTEXT_SPECIFIC, TagClass.PRIVATE)
        checkAll(iterations = 1000, Arb.uLong()) { a ->
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

            tagA shouldBeLessThan tagAC

            tagA shouldBeLessThan tagAAPP
            tagA shouldBeLessThan tagACTX
            tagA shouldBeLessThan tagAP

            tagAC shouldBeLessThan tagAAPP
            tagAC shouldBeLessThan tagACTX
            tagAC shouldBeLessThan tagAP

            val aTags = listOf(tagA, tagAC, tagAAPP, tagACTX, tagAP)
            checkAll(iterations = 1000, Arb.uLong()) { b ->
                val tagB = Asn1Element.Tag(
                    b,
                    constructed = false,
                    tagClass = TagClass.UNIVERSAL
                )

                a.compareTo(b) shouldBe tagA.compareTo(tagB)

                if (tagA.encodedTagLength < tagB.encodedTagLength) {
                    aTags.forEach { it shouldBeLessThan tagB }
                }
                if (tagA.encodedTagLength > tagB.encodedTagLength) {
                    aTags.forEach { it shouldBeGreaterThan tagB }
                }

                if (tagA.encodedTagLength == tagB.encodedTagLength) {
                    aTags.filterNot { it.tagClass == TagClass.UNIVERSAL }.forEach { it shouldBeGreaterThan tagB }
                }

            }
        }
    }
}
