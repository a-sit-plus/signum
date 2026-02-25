package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1Structure
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.TagClass
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.readOid
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
import kotlinx.serialization.modules.SerializersModule
import kotlin.jvm.JvmInline

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestCoverageGaps by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Asn1Tag INFER keeps primitive base class/constructed while overriding tag number" {
        val value = InferTagOnPrimitive(1)
        val element = Asn1Element.parse(DER.encodeToDer(value)).asStructure().children.single()

        // Current behavior: INFER still resolves to CONTEXT_SPECIFIC for class/tag class.
        element.tag.tagClass shouldBe TagClass.CONTEXT_SPECIFIC
        element.tag.isConstructed shouldBe false
        element.tag.tagValue shouldBe 9UL
        DER.decodeFromDer<InferTagOnPrimitive>(DER.encodeToDer(value)) shouldBe value
    }

    "Asn1Tag constructed=INFER keeps constructed=true for class-level structures" {
        val value = InferConstructedOnClass(7)
        val element = Asn1Element.parse(DER.encodeToDer(value))

        element.tag.tagClass shouldBe TagClass.CONTEXT_SPECIFIC
        element.tag.isConstructed shouldBe true
        element.tag.tagValue shouldBe 3UL
        DER.decodeFromDer<InferConstructedOnClass>(DER.encodeToDer(value)) shouldBe value
    }

    "Asn1Explicit requires an explicit context-specific constructed tag" {
        shouldThrow<SerializationException> {
            DER.encodeToDer(ExplicitNoTag(ExplicitlyTagged(5)))
        }
        shouldThrow<SerializationException> {
            DER.encodeToDer(
                ExplicitWrongClass(
                    ExplicitlyTagged(5)
                )
            )
        }
        shouldThrow<SerializationException> {
            DER.encodeToDer(
                ExplicitWrongConstructed(
                    ExplicitlyTagged(5)
                )
            )
        }
    }

    "Asn1BitString on non-ByteArray targets is currently ignored (no shape change)" {
        val value = InvalidBitStringTarget(1)
        val encoded = DER.encodeToDer(value)
        encoded.toHexString() shouldBe "3003020101"
        DER.decodeFromDer<InvalidBitStringTarget>(encoded) shouldBe value
    }

    "Open polymorphism by tag rejects duplicate leading-tag mappings" {
        shouldThrow<IllegalArgumentException> {
            DER {
                serializersModule = SerializersModule {
                    polymorphicByTag(DuplicateTagBase::class, serialName = "DuplicateTagBase") {
                        subtype<DuplicateTagA>()
                        subtype<DuplicateTagB>()
                    }
                }
            }
        }
    }

    "Open polymorphism by OID rejects duplicate OID mappings" {
        shouldThrow<IllegalArgumentException> {
            DER {
                serializersModule = SerializersModule {
                    polymorphicByOid(DuplicateOidBase::class, serialName = "DuplicateOidBase") {
                        subtype<DuplicateOidA>(DuplicateOidA)
                        subtype<DuplicateOidB>(DuplicateOidB)
                    }
                }
            }
        }
    }

    "Open polymorphism by OID supports custom OID selector wiring" {
        val selectorDer = DER {
            serializersModule = SerializersModule {
                polymorphicByOid(
                    CustomSelectorBase::class,
                    serialName = "CustomSelectorBase",
                    oidSelector = ::oidFromTopLevelOnly,
                ) {
                    subtype<CustomSelectorA>(CustomSelectorA)
                    subtype<CustomSelectorB>(CustomSelectorB)
                }
            }
        }

        val valueA: CustomSelectorBase = CustomSelectorA(payload = 10)
        val valueB: CustomSelectorBase = CustomSelectorB(payload = "x")
        selectorDer.decodeFromDer<CustomSelectorBase>(selectorDer.encodeToDer(valueA)) shouldBe valueA
        selectorDer.decodeFromDer<CustomSelectorBase>(selectorDer.encodeToDer(valueB)) shouldBe valueB
    }

    "encodeDefaults=false and explicitNulls=true compose as expected" {
        val der = DER {
            encodeDefaults = false
            explicitNulls = true
        }

        val withRequiredNull = CombinedFlagsModel(requiredNullable = null)
        val encoded = der.encodeToDer(withRequiredNull)

        // Only requiredNullable is emitted as ASN.1 NULL:
        // - defaultedNullable is omitted due to encodeDefaults=false
        // - trailingDefault is omitted due to encodeDefaults=false
        encoded.toHexString() shouldBe "30020500"
        der.decodeFromDer<CombinedFlagsModel>(encoded) shouldBe withRequiredNull
    }
}

@Serializable
private data class InferTagOnPrimitive(
    @Asn1Tag(
        tagNumber = 9u,
        tagClass = Asn1TagClass.INFER,
        constructed = Asn1ConstructedBit.INFER,
    )
    val value: Int,
)

@Serializable
@Asn1Tag(
    tagNumber = 3u,
    tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    constructed = Asn1ConstructedBit.INFER,
)
private data class InferConstructedOnClass(
    val value: Int,
)

@Serializable
private data class ExplicitNoTag(
    val wrapped: ExplicitlyTagged<Int>,
)

@Serializable
private data class ExplicitWrongClass(
    @Asn1Tag(
        tagNumber = 0u,
        tagClass = Asn1TagClass.UNIVERSAL,
        constructed = Asn1ConstructedBit.CONSTRUCTED,
    )
    val wrapped: ExplicitlyTagged<Int>,
)

@Serializable
private data class ExplicitWrongConstructed(
    @Asn1Tag(
        tagNumber = 0u,
        tagClass = Asn1TagClass.CONTEXT_SPECIFIC,
        constructed = Asn1ConstructedBit.PRIMITIVE,
    )
    val wrapped: ExplicitlyTagged<Int>,
)

@Serializable
private data class InvalidBitStringTarget(
    @Asn1BitString
    val value: Int,
)

private interface DuplicateTagBase

@Serializable
@JvmInline
private value class DuplicateTagA(val value: Int) : DuplicateTagBase

@Serializable
@JvmInline
private value class DuplicateTagB(val value: Int) : DuplicateTagBase

private interface DuplicateOidBase : Identifiable

@Serializable
private data class DuplicateOidA(val value: Int) : DuplicateOidBase, Identifiable by Companion {
    companion object : OidProvider<DuplicateOidA> {
        override val oid: ObjectIdentifier = ObjectIdentifier("1.2.3.4.5")
    }
}

@Serializable
private data class DuplicateOidB(val value: String) : DuplicateOidBase, Identifiable by Companion {
    companion object : OidProvider<DuplicateOidB> {
        override val oid: ObjectIdentifier = ObjectIdentifier("1.2.3.4.5")
    }
}

private interface CustomSelectorBase : Identifiable

@Serializable
private data class CustomSelectorA(
    val payload: Int,
) : CustomSelectorBase, Identifiable by Companion {
    companion object : OidProvider<CustomSelectorA> {
        override val oid: ObjectIdentifier = ObjectIdentifier("1.2.840.113549.1.1.1")
    }
}

@Serializable
private data class CustomSelectorB(
    val payload: String,
) : CustomSelectorBase, Identifiable by Companion {
    companion object : OidProvider<CustomSelectorB> {
        override val oid: ObjectIdentifier = ObjectIdentifier("1.2.840.10045.2.1")
    }
}

private fun oidFromTopLevelOnly(element: Asn1Element): ObjectIdentifier? {
    val structure = element as? Asn1Structure ?: return null
    val oid = structure.firstOrNull() as? Asn1Primitive ?: return null
    if (oid.tag != Asn1Element.Tag.OID) return null
    return runCatching { oid.readOid() }.getOrNull()
}

@Serializable
private data class CombinedFlagsModel(
    val requiredNullable: Int?,
    val defaultedNullable: Int? = null,
    val trailingDefault: Boolean = true,
)
