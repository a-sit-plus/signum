package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.Asn1Element.Tag.Template.Companion.withClass
import at.asitplus.signum.indispensable.asn1.Asn1Element.Tag.Template.Companion.without
import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.testballoon.checkAllSuites
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import com.ionspin.kotlin.bignum.integer.BigInteger
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.uLong
import de.infix.testBalloon.framework.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.testScope

val ImplicitTaggingTest by testSuite() {

    "Plain" - {
        checkAllSuites(Arb.uLong()) { tagNum ->
            val universalConstructed = Asn1Element.Tag(tagNum, constructed = true)

            "universalConstructed" {
                universalConstructed.tagValue shouldBe tagNum
                universalConstructed.isConstructed.shouldBeTrue()
                universalConstructed.tagClass shouldBe TagClass.UNIVERSAL
            }

            val universalPrimitive = Asn1Element.Tag(tagNum, constructed = false)

            "universalPrimitive" {
                universalPrimitive.tagValue shouldBe tagNum
                universalPrimitive.isConstructed.shouldBeFalse()
                universalPrimitive.tagClass shouldBe TagClass.UNIVERSAL
            }

            withData(nameFn = { "$tagNum $it" }, data = TagClass.entries) { tagClass ->
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
        checkAllSuites(Arb.uLong()) { tagNum ->
            val primitive = Asn1Primitive(tagNum, byteArrayOf())

            "setup" {
                val universalPrimitive = primitive.tag


                universalPrimitive.tagValue shouldBe tagNum
                universalPrimitive.isConstructed.shouldBeFalse()
                universalPrimitive.tagClass shouldBe TagClass.UNIVERSAL

                (primitive withImplicitTag tagNum).tag.tagClass shouldBe TagClass.CONTEXT_SPECIFIC
            }

            "convenience $tagNum" {
                val tag = Asn1Element.Tag(tagNum, constructed = false)
                (Asn1.Bool(true) withImplicitTag tag).asPrimitive().decodeToBooleanOrNull(tag) shouldBe true
                (Asn1.Int(1337) withImplicitTag tag).asPrimitive().decodeToIntOrNull(tag) shouldBe 1337
                (Asn1.Int(1337u) withImplicitTag tag).asPrimitive().decodeToUIntOrNull(tag) shouldBe 1337u
                (Asn1.Int(1337L) withImplicitTag tag).asPrimitive().decodeToLongOrNull(tag) shouldBe 1337L
                (Asn1.Int(1337uL) withImplicitTag tag).asPrimitive().decodeToULongOrNull(tag) shouldBe 1337uL
                (Asn1.Int(BigInteger(1337)) withImplicitTag tag).asPrimitive()
                    .decodeToBigIntegerOrNull(tag) shouldBe BigInteger(1337)
            }


            withData(nameFn = { "$tagNum $it" }, data = TagClass.entries) { tagClass ->

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
        checkAllSuites(Arb.uLong()) { tagNum ->
            val set = Asn1Set(listOf())

            "setup" {
                val universalConstructed = set.tag


                universalConstructed shouldBe Asn1Element.Tag.SET
                universalConstructed.isConstructed.shouldBeTrue()
                universalConstructed.tagClass shouldBe TagClass.UNIVERSAL

                (set withImplicitTag tagNum).tag.tagClass shouldBe TagClass.CONTEXT_SPECIFIC
            }

            withDataSuites(nameFn = { "$tagNum $it" }, data = TagClass.entries) { tagClass ->
                val newTagValue = tagNum / 2uL

                "setup" {
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
                }

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


}
