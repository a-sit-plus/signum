package at.asitplus.signum.indispensable.asn1

import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe

val PrettyPrintTest by matrixSuite {
    "pretty print"  {
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
}