package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.IdentifiedBy
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1Structure
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.readOid
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.serializer
import kotlin.reflect.KClass

/**
 * OID-discriminated open polymorphism helper for ASN.1 DER.
 *
 * This serializer dispatches by [ObjectIdentifier] at decode-time and by [IdentifiedBy.oid] at encode-time.
 * It is intended for open (non-sealed) polymorphic hierarchies where `ANY DEFINED BY`-style OID dispatch is needed.
 */
open class Asn1OidDiscriminatedOpenPolymorphicSerializer<T : IdentifiedBy<*>>(
    serialName: String,
    subtypes: List<SubtypeRegistration<T>>,
    private val oidSelector: (Asn1Element) -> ObjectIdentifier? = ::firstOidAlongFirstChildPathOrNull,
) : KSerializer<T>, Asn1LeadingTagsDescriptor {

    private val dispatch = Asn1OidDiscriminatedDispatch(
        serialName = serialName,
        subtypes = subtypes,
    )

    override val leadingTags: Set<Asn1Element.Tag>
        get() = dispatch.leadingTags

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(serialName, PrimitiveKind.STRING)
            .withDynamicAsn1LeadingTags { leadingTags }

    /**
     * Adds a new subtype registration after serializer construction.
     *
     * This is intentionally mutable to allow third-party libraries to extend open
     * ASN.1 polymorphic mappings in application code.
     */
    fun registerSubtype(registration: SubtypeRegistration<T>) {
        dispatch.registerSubtype(registration)
    }

    override fun serialize(encoder: Encoder, value: T) {
        if (encoder !is DerEncoder) {
            throw SerializationException(
                "${descriptor.serialName} supports ASN.1 DER format only. " +
                        "Use DER.encodeToDer(...) / DER.encodeToTlv(...) instead of non-ASN.1 formats."
            )
        }
        val selected = dispatch.serializerForEncode(value)
        @Suppress("UNCHECKED_CAST")
        encoder.encodeSerializableValue(selected as KSerializer<Any?>, value as Any?)
    }

    override fun deserialize(decoder: Decoder): T {
        if (decoder !is DerDecoder) {
            throw SerializationException(
                "${descriptor.serialName} supports ASN.1 DER format only. " +
                        "Use DER.decodeFromDer(...) / DER.decodeFromTlv(...) instead of non-ASN.1 formats."
            )
        }
        val element = decoder.peekCurrentElementOrNull()
            ?: throw SerializationException("No ASN.1 element left while decoding ${descriptor.serialName}")
        val oid = oidSelector(element)
            ?: throw SerializationException(
                "Could not extract discriminator OID from current ASN.1 element while decoding ${descriptor.serialName}"
            )
        val selected = dispatch.serializerForDecode(oid)
        @Suppress("UNCHECKED_CAST")
        return decoder.decodeCurrentElementWith(selected as DeserializationStrategy<T>)
    }

    data class SubtypeRegistration<T : IdentifiedBy<*>>(
        internal val serializer: KSerializer<out T>,
        internal val oid: ObjectIdentifier,
        internal val leadingTags: Set<Asn1Element.Tag>,
        internal val debugName: String,
    )
}

/**
 * Default OID selector for OID-discriminated open polymorphism.
 *
 * It follows the first-child path until it finds an ASN.1 OID primitive.
 * This covers common shapes such as:
 * - `SEQUENCE { OBJECT IDENTIFIER, ... }`
 * - `SEQUENCE { SEQUENCE { OBJECT IDENTIFIER, ... }, ... }`
 */
fun firstOidAlongFirstChildPathOrNull(element: Asn1Element): ObjectIdentifier? {
    val primitive = element as? Asn1Primitive
    if (primitive?.tag == Asn1Element.Tag.OID) {
        return runCatching { primitive.readOid() }.getOrNull()
    }

    val structure = element as? Asn1Structure ?: return null
    return structure.children.firstOrNull()?.let(::firstOidAlongFirstChildPathOrNull)
}

fun <T : IdentifiedBy<*>, S : T> asn1OpenPolymorphicSubtypeByOid(
    serializer: KSerializer<S>,
    oid: ObjectIdentifier,
    vararg leadingTags: Asn1Element.Tag,
): Asn1OidDiscriminatedOpenPolymorphicSerializer.SubtypeRegistration<T> =
    asn1OpenPolymorphicSubtypeByOid(serializer, oid, leadingTags.toSet())

fun <T : IdentifiedBy<*>, S : T> asn1OpenPolymorphicSubtypeByOid(
    serializer: KSerializer<S>,
    oid: ObjectIdentifier,
    leadingTags: Set<Asn1Element.Tag>,
): Asn1OidDiscriminatedOpenPolymorphicSerializer.SubtypeRegistration<T> =
    Asn1OidDiscriminatedOpenPolymorphicSerializer.SubtypeRegistration(
        serializer = serializer,
        oid = oid,
        leadingTags = leadingTags,
        debugName = serializer.descriptor.serialName
    )

fun <T : IdentifiedBy<*>, S : T> Asn1OidDiscriminatedOpenPolymorphicSerializer<T>.registerSubtype(
    serializer: KSerializer<S>,
    oid: ObjectIdentifier,
    vararg leadingTags: Asn1Element.Tag,
) {
    registerSubtype(
        asn1OpenPolymorphicSubtypeByOid(
            serializer = serializer,
            oid = oid,
            leadingTags = leadingTags.toSet(),
        )
    )
}

/**
 * Registers an OID-discriminated subtype with strict source typing.
 *
 * [oidSource] must match the subtype's declared [IdentifiedBy] source type [I].
 * When [leadingTags] are omitted, they are inferred from the subtype serializer descriptor.
 * If inference is not possible, explicit tags must be provided.
 */
@OptIn(ExperimentalSerializationApi::class)
inline fun <reified S, I : Identifiable, T> Asn1OidDiscriminatedOpenPolymorphicSerializer<T>.registerSubtype(
    oidSource: I,
    vararg leadingTags: Asn1Element.Tag,
) where S : T, T : IdentifiedBy<I> {
    val subtypeSerializer = serializer<S>()
    val resolvedLeadingTags = leadingTags.toSet().ifEmpty {
        inferOpenPolymorphicSubtypeLeadingTagsOrNull(subtypeSerializer.descriptor)
            ?: throw IllegalArgumentException(
                cannotInferOpenPolymorphicSubtypeLeadingTagsMessage(subtypeSerializer.descriptor.serialName)
            )
    }

    registerSubtype(
        asn1OpenPolymorphicSubtypeByOid(
            serializer = subtypeSerializer,
            oid = oidSource.oid,
            leadingTags = resolvedLeadingTags,
        )
    )
}

/**
 * Registers an OID-discriminated subtype while letting call-sites infer [S] from a class literal.
 */
@OptIn(ExperimentalSerializationApi::class)
inline fun <I : Identifiable, T : IdentifiedBy<I>, reified S : T>
        Asn1OidDiscriminatedOpenPolymorphicSerializer<T>.registerSubtype(
    subtype: KClass<S>,
    oidSource: I,
    vararg leadingTags: Asn1Element.Tag,
) {
    // Uses the class literal for generic inference ergonomics.
    @Suppress("UNUSED_VARIABLE")
    val ignored = subtype
    registerSubtype<S, I, T>(
        oidSource = oidSource,
        *leadingTags,
    )
}

@PublishedApi
internal fun inferOpenPolymorphicSubtypeLeadingTagsOrNull(
    descriptor: SerialDescriptor,
): Set<Asn1Element.Tag>? = when (val resolution = descriptor.possibleLeadingTagsForAsn1()) {
    is Asn1LeadingTagsResolution.Exact -> resolution.tags
    Asn1LeadingTagsResolution.UnknownInfer -> null
}

@PublishedApi
internal fun cannotInferOpenPolymorphicSubtypeLeadingTagsMessage(
    serialName: String,
): String =
    "Cannot infer leading ASN.1 tag(s) for subtype '$serialName'. " +
            "Provide leadingTags explicitly."
