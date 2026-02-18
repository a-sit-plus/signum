package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.modules.SerializersModuleBuilder
import kotlinx.serialization.serializer
import kotlin.reflect.KClass

/**
 * Supplies discriminator OIDs for OID-discriminated open polymorphism DSL registrations.
 */
interface OidProvider<out S : Identifiable> : Identifiable

/**
 * Marker for ASN.1 open-polymorphism registration DSL scopes.
 */
@DslMarker
annotation class Asn1OpenPolymorphismDsl

/**
 * DSL builder for tag-discriminated open polymorphism.
 *
 * Each registered subtype must contribute at least one leading tag (explicitly or inferable).
 */
@Asn1OpenPolymorphismDsl
class Asn1OpenPolymorphismByTagBuilder<T : Any> internal constructor() {
    private val registrations = mutableListOf<Asn1TagDiscriminatedSubtypeRegistration<T>>()

    /**
     * Registers one tag-discriminated subtype.
     *
     * @throws IllegalArgumentException if leading tags cannot be inferred for empty [leadingTags]
     */
    @Throws(IllegalArgumentException::class)
    fun <S : T> subtype(
        serializer: KSerializer<S>,
        leadingTags: Set<Asn1Element.Tag>,
        matches: (T) -> Boolean,
    ) {
        val resolvedLeadingTags = leadingTags.ifEmpty {
            inferOpenPolymorphicSubtypeLeadingTagsOrNull(serializer.descriptor)
                ?: throw IllegalArgumentException(
                    cannotInferOpenPolymorphicSubtypeLeadingTagsMessage(serializer.descriptor.serialName)
                )
        }
        registrations += Asn1TagDiscriminatedSubtypeRegistration(
            serializer = serializer,
            leadingTags = resolvedLeadingTags,
            matches = matches,
            debugName = serializer.descriptor.serialName,
        )
    }

    @OptIn(ExperimentalSerializationApi::class)
    inline fun <reified S : T> subtype(
        vararg leadingTags: Asn1Element.Tag,
        noinline matches: (T) -> Boolean = { it is S },
    ) {
        subtype(
            serializer = serializer<S>(),
            leadingTags = leadingTags.toSet(),
            matches = matches,
        )
    }

    /**
     * Builds the serializer from collected registrations.
     *
     * @throws SerializationException if no subtype has been registered
     */
    @Throws(SerializationException::class)
    internal fun build(serialName: String): KSerializer<T> {
        if (registrations.isEmpty()) {
            throw SerializationException("At least one subtype registration is required for $serialName")
        }
        return Asn1TagDiscriminatedOpenPolymorphicSerializer(
            serialName = serialName,
            subtypes = registrations.toList(),
        )
    }

}

/**
 * DSL builder for OID-discriminated open polymorphism.
 *
 * Each registered subtype binds one OID plus one or more leading tags.
 */
@Asn1OpenPolymorphismDsl
class Asn1OpenPolymorphismByOidBuilder<T : Identifiable> internal constructor() {
    private val registrations = mutableListOf<Asn1OidDiscriminatedSubtypeRegistration<T>>()


    /**
     * Registers one OID-discriminated subtype.
     *
     * @throws IllegalArgumentException if leading tags cannot be inferred for empty [leadingTags]
     */
    @Throws(IllegalArgumentException::class)
    fun <S : T> subtype(
        serializer: KSerializer<S>,
        provider: OidProvider<S>,
        leadingTags: Set<Asn1Element.Tag>,
        matches: (T) -> Boolean,
    ) {
        val resolvedLeadingTags = leadingTags.ifEmpty {
            inferOpenPolymorphicSubtypeLeadingTagsOrNull(serializer.descriptor)
                ?: throw IllegalArgumentException(
                    cannotInferOpenPolymorphicSubtypeLeadingTagsMessage(serializer.descriptor.serialName)
                )
        }
        registrations += Asn1OidDiscriminatedSubtypeRegistration(
            serializer = serializer,
            oid = provider.oid,
            leadingTags = resolvedLeadingTags,
            matches = matches,
            debugName = serializer.descriptor.serialName,
        )
    }

    @OptIn(ExperimentalSerializationApi::class)
    inline fun <reified S : T> subtype(
        provider: OidProvider<S>,
        vararg leadingTags: Asn1Element.Tag,
        noinline matches: (T) -> Boolean = { it is S },
    ) {
        subtype(
            serializer = serializer<S>(),
            provider = provider,
            leadingTags = leadingTags.toSet(),
            matches = matches,
        )
    }

    /**
     * Builds the serializer from collected registrations.
     *
     * @throws SerializationException if no subtype has been registered
     */
    @Throws(SerializationException::class)
    internal fun build(
        serialName: String,
        oidSelector: (Asn1Element) -> ObjectIdentifier?,
    ): KSerializer<T> {
        if (registrations.isEmpty()) {
            throw SerializationException("At least one subtype registration is required for $serialName")
        }
        return Asn1OidDiscriminatedOpenPolymorphicSerializer(
            serialName = serialName,
            subtypes = registrations.toList(),
            oidSelector = oidSelector,
        )
    }
}

/**
 * Builds a tag-discriminated ASN.1 open-polymorphic serializer.
 *
 * @throws SerializationException if no subtype is registered
 * @throws IllegalArgumentException if subtype tag inference fails
 */
@Throws(SerializationException::class, IllegalArgumentException::class)
fun <T : Any> asn1OpenPolymorphicByTagSerializer(
    serialName: String,
    block: Asn1OpenPolymorphismByTagBuilder<T>.() -> Unit,
): KSerializer<T> = Asn1OpenPolymorphismByTagBuilder<T>()
    .apply(block)
    .build(serialName)

/**
 * Builds an OID-discriminated ASN.1 open-polymorphic serializer.
 *
 * @throws SerializationException if no subtype is registered
 * @throws IllegalArgumentException if subtype tag inference fails
 */
@Throws(SerializationException::class, IllegalArgumentException::class)
fun <T : Identifiable> asn1OpenPolymorphicByOidSerializer(
    serialName: String,
    oidSelector: (Asn1Element) -> ObjectIdentifier? = ::oidFrom,
    block: Asn1OpenPolymorphismByOidBuilder<T>.() -> Unit,
): KSerializer<T> = Asn1OpenPolymorphismByOidBuilder<T>()
    .apply(block)
    .build(serialName, oidSelector)

/**
 * Registers a tag-discriminated ASN.1 open-polymorphic serializer as contextual serializer.
 *
 * @throws SerializationException if no subtype is registered
 * @throws IllegalArgumentException if subtype tag inference fails
 */
@Throws(SerializationException::class, IllegalArgumentException::class)
fun <T : Any> SerializersModuleBuilder.polymorphicByTag(
    baseClass: KClass<T>,
    serialName: String = "Asn1OpenPolymorphicByTag",
    block: Asn1OpenPolymorphismByTagBuilder<T>.() -> Unit,
) {
    contextual(baseClass, asn1OpenPolymorphicByTagSerializer(serialName, block))
}

/**
 * Registers an OID-discriminated ASN.1 open-polymorphic serializer as contextual serializer.
 *
 * @throws SerializationException if no subtype is registered
 * @throws IllegalArgumentException if subtype tag inference fails
 */
@Throws(SerializationException::class, IllegalArgumentException::class)
fun <T : Identifiable> SerializersModuleBuilder.polymorphicByOid(
    baseClass: KClass<T>,
    serialName: String = "Asn1OpenPolymorphicByOid",
    oidSelector: (Asn1Element) -> ObjectIdentifier? = ::oidFrom,
    block: Asn1OpenPolymorphismByOidBuilder<T>.() -> Unit,
) {
    contextual(baseClass, asn1OpenPolymorphicByOidSerializer(serialName, oidSelector, block))
}
