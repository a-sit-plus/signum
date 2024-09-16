package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.Asn1Element.Tag.Template.Companion.withClass
import at.asitplus.signum.indispensable.asn1.Asn1Element.Tag.Template.Companion.without
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.uLong
import io.kotest.property.checkAll

class ImplicitTaggingTest : FreeSpec({

    "Plain" - {
        checkAll(Arb.uLong()) { tagNum ->
            val universalConstructed = Asn1Element.Tag(tagNum, constructed = true)

            universalConstructed.tagValue shouldBe tagNum
            universalConstructed.isConstructed.shouldBeTrue()
            universalConstructed.tagClass shouldBe TagClass.UNIVERSAL

            val universalPrimitive = Asn1Element.Tag(tagNum, constructed = false)


            universalPrimitive.tagValue shouldBe tagNum
            universalPrimitive.isConstructed.shouldBeFalse()
            universalPrimitive.tagClass shouldBe TagClass.UNIVERSAL

            withData(nameFn = { "$tagNum $it" }, TagClass.entries) { tagClass ->
                val classy = universalConstructed withClass tagClass
                classy.tagClass shouldBe tagClass
                (universalConstructed without CONSTRUCTED).isConstructed shouldBe false
                (classy without CONSTRUCTED).also {
                    it.isConstructed shouldBe false
                    (universalConstructed withClass tagClass without CONSTRUCTED) shouldBe it
                }

                val classyPrimitive = universalPrimitive withClass tagClass
                classyPrimitive.tagClass shouldBe tagClass
                (universalPrimitive without CONSTRUCTED).also {
                    it.isConstructed shouldBe false
                    it shouldBe universalPrimitive
                }
                (classyPrimitive without CONSTRUCTED) shouldBe classyPrimitive

            }


        }
    }

    "Primitive" - {
        checkAll(Arb.uLong()) { tagNum ->
            val primitive = Asn1Primitive(tagNum, byteArrayOf())

            val universalPrimitive = primitive.tag


            universalPrimitive.tagValue shouldBe tagNum
            universalPrimitive.isConstructed.shouldBeFalse()
            universalPrimitive.tagClass shouldBe TagClass.UNIVERSAL

            (primitive withImplicitTag tagNum).tag.tagClass shouldBe TagClass.CONTEXT_SPECIFIC

            withData(nameFn = { "$tagNum $it" }, TagClass.entries) { tagClass ->

                val newTagValue = tagNum / 2uL;
                val newTagObject = Asn1Element.Tag(newTagValue, constructed = true) //test CONSTRUCTED override
                val taggedElement = primitive withImplicitTag (newTagValue withClass tagClass)
                val taggedElementFromTag = primitive withImplicitTag (newTagObject withClass tagClass)
                taggedElementFromTag shouldBe taggedElement

                val classyPrimitive = taggedElement.tag
                classyPrimitive.tagClass shouldBe tagClass
                classyPrimitive.tagValue shouldBe newTagValue
                classyPrimitive.isConstructed.shouldBeFalse()
                (primitive withImplicitTag (newTagValue withClass tagClass without CONSTRUCTED)).also {
                    it.tag shouldBe classyPrimitive
                }

                (primitive withImplicitTag (newTagObject withClass tagClass)).also {
                    it.tag shouldBe classyPrimitive
                    it.tag shouldBe (primitive withImplicitTag (newTagObject withClass tagClass without CONSTRUCTED)).tag
                }

                val encoded = taggedElement.derEncoded
                Asn1Element.parse(encoded).derEncoded shouldBe encoded
            }
        }
    }


    "Constructed" - {
        checkAll(Arb.uLong()) { tagNum ->
            val set = Asn1Set(listOf())

            val universalConstructed = set.tag


            universalConstructed shouldBe Asn1Element.Tag.SET
            universalConstructed.isConstructed.shouldBeTrue()
            universalConstructed.tagClass shouldBe TagClass.UNIVERSAL

            (set withImplicitTag tagNum).tag.tagClass shouldBe TagClass.CONTEXT_SPECIFIC

            withData(nameFn = { "$tagNum $it" }, TagClass.entries) { tagClass ->

                val newTagValue = tagNum / 2uL

                val taggedElement = set withImplicitTag (newTagValue withClass tagClass)
                val classySet = taggedElement.tag
                classySet.tagClass shouldBe tagClass
                classySet.tagValue shouldBe newTagValue
                classySet.isConstructed.shouldBeTrue()
                (set withImplicitTag (newTagValue withClass tagClass without CONSTRUCTED)).also {
                    it.tag.isConstructed.shouldBeFalse()
                    it.tag.tagValue shouldBe newTagValue
                    it.tag.tagClass shouldBe tagClass
                }

                val encoded = taggedElement.derEncoded
                Asn1Element.parse(encoded).derEncoded shouldBe encoded

                val primitive = set withImplicitTag (newTagValue without CONSTRUCTED)
                primitive.tag.tagClass shouldBe TagClass.CONTEXT_SPECIFIC
                primitive.tag.isConstructed.shouldBeFalse()
                primitive.tag.tagValue shouldBe newTagValue

                withData(true, false) { constructed ->
                    val newTag = Asn1Element.Tag(newTagValue, constructed = constructed)
                    val taggedElement = set withImplicitTag (newTag withClass tagClass)
                    val classySet = taggedElement.tag
                    classySet.tagClass shouldBe tagClass
                    classySet.tagValue shouldBe newTagValue
                    classySet.isConstructed shouldBe newTag.isConstructed
                    (set withImplicitTag (newTag withClass tagClass without CONSTRUCTED)).also {
                        it.tag.isConstructed.shouldBeFalse()
                        it.tag.tagValue shouldBe newTagValue
                        it.tag.tagClass shouldBe tagClass
                    }

                }


            }
        }
    }


})