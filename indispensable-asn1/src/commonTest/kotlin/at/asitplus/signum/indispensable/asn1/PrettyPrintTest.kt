package io.kotest.provided.at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.Asn1CustomStructure
import at.asitplus.signum.indispensable.asn1.TagClass
import at.asitplus.test.FreeSpec
import io.kotest.matchers.shouldBe

class PrettyPrintTest: FreeSpec( {
    "pretty print" - {
        val structure = Asn1CustomStructure(
            children = emptyList(),
            tag = 0UL,
            tagClass = TagClass.PRIVATE,
            sortChildren = false,
            shouldBeSorted = false
        )
        structure.prettyPrint() shouldBe """
        PRIVATE 0 (=E0), length=0, overallLength=2
        {
        
        }""".trimIndent()
    }
})