package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestPolymorphismAndChoice by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Number of elements" {
        val withThreeOtherNull = WithThreeNullable("first", null, "3")

        DER.encodeToDer(withThreeOtherNull).apply {
            toHexString() shouldBe "300a0c0566697273740c0133"
            DER.decodeFromDer<WithThreeNullable>(this) shouldBe withThreeOtherNull
        }

        val withThreeOther = WithThreeNullable("first", 2, "3")

        DER.encodeToDer(withThreeOther).apply {
            toHexString() shouldBe "300d0c0566697273740201020c0133"
            DER.decodeFromDer<WithThreeNullable>(this) shouldBe withThreeOther
        }

        val without = Without
        val withOne = WithOne("")
        val withTwo = WithTwo("1", "2")
        val withTwoOther = WithTwoOther("1", 2)
        val withThree = WithThree("1", "3", "3")

        DER.encodeToDer(without).apply {
            toHexString() shouldBe "3000"
            DER.decodeFromDer<Without>(this) shouldBe without
        }

        shouldThrow<SerializationException> { DER.decodeFromDer<Without>("30020c00".hexToByteArray()) }

        DER.encodeToDer(withOne).apply {
            toHexString() shouldBe "30020c00"
            DER.decodeFromDer<WithOne>(this) shouldBe withOne
        }

        DER.encodeToDer(withTwo).apply {
            toHexString() shouldBe "30060c01310c0132"
            DER.decodeFromDer<WithTwo>(this) shouldBe withTwo
        }

        DER.encodeToDer(withTwoOther).apply {
            toHexString() shouldBe "30060c0131020102"
            DER.decodeFromDer<WithTwoOther>(this) shouldBe withTwoOther
        }

        DER.encodeToDer(withThree).apply {
            toHexString() shouldBe "30090c01310c01330c0133"
            DER.decodeFromDer<WithThree>(this) shouldBe withThree
        }
    }

    "Polymorphic" {
        val without = Without
        val withOne = WithOne("")
        val withTwo = WithTwo("1", "2")
        val withTwoOther = WithTwoOther("1", 2)
        val withThree = WithThree("1", "3", "3")

        shouldThrow<SerializationException> {
            DER.decodeFromDer<List<AnInterface>>(
                "3082017730430c3f61742e61736974706c75732e7369676e756d2e696e64697370656e7361626c652e61736e312e73657269616c697a6174696f6e2e6170692e576974686f7574300030450c3f61742e61736974706c75732e7369676e756d2e696e64697370656e7361626c652e61736e312e73657269616c697a6174696f6e2e6170692e576974684f6e6530020c0030490c3f61742e61736974706c75732e7369676e756d2e696e64697370656e7361626c652e61736e312e73657269616c697a6174696f6e2e6170692e5769746854776f30060c01310c0132304e0c4461742e61736974706c75732e7369676e756d2e696e64697370656e7361626c652e61736e312e73657269616c697a6174696f6e2e6170692e5769746854776f4f7468657230060c0131020102304e0c4161742e61736974706c75732e7369676e756d2e696e64697370656e7361626c652e61736e312e73657269616c697a6174696f6e2e6170692e57697468546872656530090c01310c01330c0133".hexToByteArray()
            )
        }

        DER.decodeFromDer<List<AnInterface>>(
            DER.encodeToDer(listOf(without, withOne, withTwo, withTwoOther, withThree))
        ) shouldBe listOf(without, withOne, withTwo, withTwoOther, withThree)
    }

    "Choice polymorphism (sealed only)" {
        val intChoice = ChoiceContainer(ChoiceInt(7))
        val taggedStringChoice = ChoiceContainer(ChoiceTaggedString("foo"))

        DER.decodeFromDer<ChoiceContainer>(DER.encodeToDer(intChoice)) shouldBe intChoice
        DER.decodeFromDer<ChoiceContainer>(DER.encodeToDer(taggedStringChoice)) shouldBe taggedStringChoice

        val list = listOf<ChoiceInterface>(ChoiceInt(1), ChoiceTaggedString("bar"))
        DER.decodeFromDer<List<ChoiceInterface>>(DER.encodeToDer(list)) shouldBe list
    }

    "Choice ambiguity is rejected at runtime" {
        val encoded = DER.encodeToDer<AmbiguousChoice>(AmbiguousChoiceA("foo"))
        shouldThrow<SerializationException> {
            DER.decodeFromDer<AmbiguousChoice>(encoded)
        }
    }
}

@Serializable
sealed interface AnInterface

// @formatter:off
@Serializable object Without : AnInterface
@Serializable data class WithOne(val first: String) : AnInterface
@Serializable data class WithTwo(val first: String, val second: String) : AnInterface
@Serializable data class WithTwoOther(val first: String, val second: Int) : AnInterface
@Serializable data class WithThree(val first: String, val second: String, val third: String) : AnInterface

@Serializable data class WithThreeNullable(val first: String, val second: Int?, val third: String)
// @formatter:on

@Serializable
@Asn1nnotation(asChoice = true)
sealed interface ChoiceInterface

@Serializable
data class ChoiceContainer(val choice: ChoiceInterface)

@Serializable
data class ChoiceInt(val value: Int) : ChoiceInterface

@Serializable
@Asn1nnotation(tagNumber = 1, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
data class ChoiceTaggedString(val value: String) : ChoiceInterface

@Serializable
@Asn1nnotation(asChoice = true)
sealed interface AmbiguousChoice

@Serializable
data class AmbiguousChoiceA(val value: String) : AmbiguousChoice

@Serializable
data class AmbiguousChoiceB(val value: String) : AmbiguousChoice
