package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.serializer
import kotlinx.serialization.modules.SerializersModuleBuilder
import kotlin.reflect.KClass

@DslMarker
annotation class Asn1OpenPolymorphismDsl

@Asn1OpenPolymorphismDsl
class Asn1OpenPolymorphismByTagBuilder<T : Any> internal constructor() {
    private val registrations = mutableListOf<Asn1TagDiscriminatedSubtypeRegistration<T>>()

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

@Asn1OpenPolymorphismDsl
class Asn1OpenPolymorphismByOidBuilder<T : Any> internal constructor() {
    private val registrations = mutableListOf<Asn1OidDiscriminatedSubtypeRegistration<T>>()

    fun <S : T> subtype(
        serializer: KSerializer<S>,
        oid: ObjectIdentifier,
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
            oid = oid,
            leadingTags = resolvedLeadingTags,
            matches = matches,
            debugName = serializer.descriptor.serialName,
        )
    }

    @OptIn(ExperimentalSerializationApi::class)
    inline fun <reified S : T> subtype(
        oid: ObjectIdentifier,
        vararg leadingTags: Asn1Element.Tag,
        noinline matches: (T) -> Boolean = { it is S },
    ) {
        subtype(
            serializer = serializer<S>(),
            oid = oid,
            leadingTags = leadingTags.toSet(),
            matches = matches,
        )
    }

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

fun <T : Any> asn1OpenPolymorphicByTagSerializer(
    serialName: String,
    block: Asn1OpenPolymorphismByTagBuilder<T>.() -> Unit,
): KSerializer<T> = Asn1OpenPolymorphismByTagBuilder<T>()
    .apply(block)
    .build(serialName)

fun <T : Any> asn1OpenPolymorphicByOidSerializer(
    serialName: String,
    oidSelector: (Asn1Element) -> ObjectIdentifier? = ::firstOidAlongFirstChildPathOrNull,
    block: Asn1OpenPolymorphismByOidBuilder<T>.() -> Unit,
): KSerializer<T> = Asn1OpenPolymorphismByOidBuilder<T>()
    .apply(block)
    .build(serialName, oidSelector)

fun <T : Any> SerializersModuleBuilder.polymorphicByTag(
    baseClass: KClass<T>,
    serialName: String = baseClass.qualifiedName ?: "Asn1OpenPolymorphicByTag",
    block: Asn1OpenPolymorphismByTagBuilder<T>.() -> Unit,
) {
    contextual(baseClass, asn1OpenPolymorphicByTagSerializer(serialName, block))
}

fun <T : Any> SerializersModuleBuilder.polymorphicByOid(
    baseClass: KClass<T>,
    serialName: String = baseClass.qualifiedName ?: "Asn1OpenPolymorphicByOid",
    oidSelector: (Asn1Element) -> ObjectIdentifier? = ::firstOidAlongFirstChildPathOrNull,
    block: Asn1OpenPolymorphismByOidBuilder<T>.() -> Unit,
) {
    contextual(baseClass, asn1OpenPolymorphicByOidSerializer(serialName, oidSelector, block))
}

