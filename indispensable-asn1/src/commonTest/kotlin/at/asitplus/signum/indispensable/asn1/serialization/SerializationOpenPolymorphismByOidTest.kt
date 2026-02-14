package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.IdentifiedBy
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException

private val oidA = ObjectIdentifier("1.2.840.113549.1.1.1")
private val oidB = ObjectIdentifier("1.2.840.10045.2.1")
private val oidC = ObjectIdentifier("1.3.101.110")

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestOpenPolymorphismByOid by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "Open-polymorphic OID dispatch round-trips with registered subtypes" {
        val intValue: OpenByOid = OpenByOidInt(value = 7)
        val strValue: OpenByOid = OpenByOidString(value = "hello")

        DER.decodeFromDer<OpenByOid>(DER.encodeToDer(intValue)) shouldBe intValue
        DER.decodeFromDer<OpenByOid>(DER.encodeToDer(strValue)) shouldBe strValue
    }

    "Default OID selector follows first-child path for nested algorithm identifiers" {
        val nestedA: OpenByNestedOid = OpenByNestedOidA(payload = 1)
        val nestedB: OpenByNestedOid = OpenByNestedOidB(payload = "x")

        DER.decodeFromDer<OpenByNestedOid>(DER.encodeToDer(nestedA)) shouldBe nestedA
        DER.decodeFromDer<OpenByNestedOid>(DER.encodeToDer(nestedB)) shouldBe nestedB
    }

    "Unregistered OID subtype can be hooked by extending registrations" {
        val boolValue: OpenByOid = OpenByOidBool(value = true)
        val extensibleSerializer = createOpenByOidSerializer("OpenByOidExtensible")

        shouldThrow<SerializationException> {
            DER.encodeToDer(extensibleSerializer, boolValue)
        }.message.shouldContain("No registered open-polymorphic subtype")

        val encodedViaConcreteSerializer = DER.encodeToDer(OpenByOidBool.serializer(), OpenByOidBool(value = true))
        shouldThrow<SerializationException> {
            DER.decodeFromDer(encodedViaConcreteSerializer, extensibleSerializer)
        }.message.shouldContain("for OID")

        extensibleSerializer.registerSubtype(
            subtype = OpenByOidBool::class,
            oidSource = oidC,
        )

        val encoded = DER.encodeToDer(extensibleSerializer, boolValue)
        DER.decodeFromDer(encoded, extensibleSerializer) shouldBe boolValue
    }

    "Missing OID discriminator fails decode" {
        val encodedNoOid = DER.encodeToDer(NoOidEnvelope.serializer(), NoOidEnvelope(value = 1))
        shouldThrow<SerializationException> {
            DER.decodeFromDer(encodedNoOid, OpenByOidSerializer)
        }.message.shouldContain("Could not extract discriminator OID")
    }

    "Nullable OID-open-polymorphic property participates in ambiguity checks" {
        val ambiguous = NullableOpenByOidThenList(
            first = null,
            second = listOf(1, 2),
        )
        shouldThrow<SerializationException> {
            DER.encodeToDer(ambiguous)
        }.message.shouldContain("Ambiguous ASN.1 layout")
    }

    "Tagging sibling SEQUENCE disambiguates nullable OID-open-polymorphic layout" {
        val withoutFirst = NullableOpenByOidThenTaggedList(
            first = null,
            second = listOf(9),
        )
        val withFirst = NullableOpenByOidThenTaggedList(
            first = OpenByOidInt(value = 3),
            second = null,
        )
        DER.decodeFromDer<NullableOpenByOidThenTaggedList>(DER.encodeToDer(withoutFirst)) shouldBe withoutFirst
        DER.decodeFromDer<NullableOpenByOidThenTaggedList>(DER.encodeToDer(withFirst)) shouldBe withFirst
    }
}

@Serializable(with = OpenByOidSerializer::class)
interface OpenByOid : Identifiable, IdentifiedBy<ObjectIdentifier> {
    override val oidSource: ObjectIdentifier
        get() = oid
}

@Serializable
data class OpenByOidInt(
    override val oid: ObjectIdentifier = oidA,
    val value: Int,
) : OpenByOid {
    override val oidSource: ObjectIdentifier
        get() = oid
}

@Serializable
data class OpenByOidString(
    override val oid: ObjectIdentifier = oidB,
    val value: String,
) : OpenByOid {
    override val oidSource: ObjectIdentifier
        get() = oid
}

@Serializable
data class OpenByOidBool(
    override val oid: ObjectIdentifier = oidC,
    val value: Boolean,
) : OpenByOid {
    override val oidSource: ObjectIdentifier
        get() = oid
}

private fun createOpenByOidSerializer(
    serialName: String,
): Asn1OidDiscriminatedOpenPolymorphicSerializer<OpenByOid> =
    Asn1OidDiscriminatedOpenPolymorphicSerializer(
        serialName = serialName,
        subtypes = openByOidSubtypeRegistrations(),
    )

private fun openByOidSubtypeRegistrations() = listOf(
    asn1OpenPolymorphicSubtypeByOid<OpenByOid, OpenByOidInt>(
        serializer = OpenByOidInt.serializer(),
        oid = oidA,
        leadingTags = setOf(Asn1Element.Tag.SEQUENCE),
    ),
    asn1OpenPolymorphicSubtypeByOid<OpenByOid, OpenByOidString>(
        serializer = OpenByOidString.serializer(),
        oid = oidB,
        leadingTags = setOf(Asn1Element.Tag.SEQUENCE),
    ),
)

object OpenByOidSerializer : Asn1OidDiscriminatedOpenPolymorphicSerializer<OpenByOid>(
    serialName = "OpenByOid",
    subtypes = openByOidSubtypeRegistrations(),
)

@Serializable
data class NoOidEnvelope(
    val value: Int,
)

@Serializable
data class NullableOpenByOidThenList(
    val first: OpenByOid?,
    val second: List<Int>?,
)

@Serializable
data class NullableOpenByOidThenTaggedList(
    val first: OpenByOid?,
    @Asn1Tag(tagNumber = 42u)
    val second: List<Int>?,
)

@Serializable(with = OpenByNestedOidSerializer::class)
interface OpenByNestedOid : Identifiable, IdentifiedBy<ObjectIdentifier> {
    override val oidSource: ObjectIdentifier
        get() = oid
}

@Serializable
data class NestedAlgorithmIdentifier(
    val oid: ObjectIdentifier,
)

@Serializable
data class OpenByNestedOidA(
    val algorithm: NestedAlgorithmIdentifier = NestedAlgorithmIdentifier(oidA),
    val payload: Int,
) : OpenByNestedOid {
    override val oid: ObjectIdentifier
        get() = algorithm.oid
    override val oidSource: ObjectIdentifier
        get() = oid
}

@Serializable
data class OpenByNestedOidB(
    val algorithm: NestedAlgorithmIdentifier = NestedAlgorithmIdentifier(oidB),
    val payload: String,
) : OpenByNestedOid {
    override val oid: ObjectIdentifier
        get() = algorithm.oid
    override val oidSource: ObjectIdentifier
        get() = oid
}

object OpenByNestedOidSerializer : Asn1OidDiscriminatedOpenPolymorphicSerializer<OpenByNestedOid>(
    serialName = "OpenByNestedOid",
    subtypes = listOf(
        asn1OpenPolymorphicSubtypeByOid<OpenByNestedOid, OpenByNestedOidA>(
            serializer = OpenByNestedOidA.serializer(),
            oid = oidA,
            leadingTags = setOf(Asn1Element.Tag.SEQUENCE),
        ),
        asn1OpenPolymorphicSubtypeByOid<OpenByNestedOid, OpenByNestedOidB>(
            serializer = OpenByNestedOidB.serializer(),
            oid = oidB,
            leadingTags = setOf(Asn1Element.Tag.SEQUENCE),
        ),
    )
)
