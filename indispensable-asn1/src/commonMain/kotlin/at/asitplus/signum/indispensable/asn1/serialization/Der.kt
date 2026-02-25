package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.internals.ImplementationError
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.serializer
import kotlin.reflect.typeOf


/**
 * Marker format type for ASN.1 DER serialization via kotlinx.serialization.
 *
 * Use the top-level [at.asitplus.signum.indispensable.asn1.serialization.api.DER] instance
 * or create a custom instance through `DER { }`.
 */
class Der internal constructor(
    val configuration: DerConfiguration = DerConfiguration()
)

/**
 * DER format options.
 *
 * @property encodeDefaults if `true`, default-valued properties are encoded.
 * If `false`, default-valued properties are omitted.
 * @property explicitNulls if `true`, nullable properties are encoded as ASN.1 `NULL` by default.
 * If `false`, nullable `null` values are omitted by default.
 * @property reEmitAsn1Backed if `true`, [Asn1Backed] values with preserved source TLV are emitted
 * exactly as originally decoded.
 * @property serializersModule serializers used for contextual/open-polymorphic resolution.
 */
data class DerConfiguration(
    val encodeDefaults: Boolean = true,
    val explicitNulls: Boolean = false,
    val reEmitAsn1Backed: Boolean = false,
    val serializersModule: SerializersModule = EmptySerializersModule(),
)

/**
 * Builder for [DerConfiguration], used by `DER { ... }`.
 *
 * - [encodeDefaults]: include/exclude default-valued properties.
 * - [explicitNulls]: encode `null` as ASN.1 `NULL` or omit nullable values.
 * - [serializersModule]: module used for contextual/open-polymorphic serializers.
 */
class DerBuilder internal constructor() {
    var encodeDefaults: Boolean = true
    var explicitNulls: Boolean = false
    var serializersModule: SerializersModule = EmptySerializersModule()

    internal fun build() = DerConfiguration(
        encodeDefaults = encodeDefaults,
        explicitNulls = explicitNulls,
        serializersModule = serializersModule,
    )
}

//all of the below must be extensions that statically resolve to allow for shadowing

/**
 * Encodes [value] into DER using the inferred serializer for [T].
 */
@ExperimentalSerializationApi
inline fun <reified T> Der.encodeToDer(value: T) =
    encodeToDer(configuration.serializersModule.serializer(typeOf<T>()), value)

/**
 * Encodes [value] into a single ASN.1 TLV element using the inferred serializer for [T].
 */
@ExperimentalSerializationApi
inline fun <reified T> Der.encodeToTlv(value: T) =
    encodeToTlv(configuration.serializersModule.serializer(typeOf<T>()), value)


/**
 * Decodes [source] from DER using the inferred deserializer for [T].
 */
@ExperimentalSerializationApi
@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
@kotlin.internal.LowPriorityInOverloadResolution
inline fun <reified T> Der.decodeFromDer(source: ByteArray): T =
    decodeFromDer(source, configuration.serializersModule.serializer(typeOf<T>())) as T

/**
 * Decodes [source] from a single ASN.1 TLV element using the inferred deserializer for [T].
 */
@ExperimentalSerializationApi
@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
@kotlin.internal.LowPriorityInOverloadResolution
inline fun <reified T> Der.decodeFromTlv(source: Asn1Element): T =
    decodeFromTlv(source, configuration.serializersModule.serializer(typeOf<T>())) as T

/**
 * Encodes [value] with the given [serializer] into DER bytes.
 *
 * @throws kotlinx.serialization.SerializationException if descriptor/tag/nullability constraints are violated
 */
@ExperimentalSerializationApi
@Throws(kotlinx.serialization.SerializationException::class)
fun <T> Der.encodeToDer(serializer: SerializationStrategy<T>, value: T): ByteArray {
    val layoutPlan = DerLayoutPlanContext(configuration).also { it.prime(serializer.descriptor) }
    val encoder = DerEncoder(
        serializersModule = configuration.serializersModule,
        formatConfiguration = configuration,
        layoutPlan = layoutPlan,
    )
    encoder.encodeSerializableValue(serializer, value)
    return Buffer().also { encoder.writeTo(it) }.readByteArray()
}

/**
 * Encodes [value] with the given [serializer] into a single ASN.1 TLV element.
 *
 * @throws kotlinx.serialization.SerializationException if descriptor/tag/nullability constraints are violated
 * @throws at.asitplus.signum.internals.ImplementationError if serialization produced more than one top-level element
 */
@ExperimentalSerializationApi
@Throws(kotlinx.serialization.SerializationException::class, ImplementationError::class)
fun <T> Der.encodeToTlv(serializer: SerializationStrategy<T>, value: T): Asn1Element {
    val layoutPlan = DerLayoutPlanContext(configuration).also { it.prime(serializer.descriptor) }
    val encoder = DerEncoder(
        serializersModule = configuration.serializersModule,
        formatConfiguration = configuration,
        layoutPlan = layoutPlan,
    )
    encoder.encodeSerializableValue(serializer, value)
    return encoder.encodeToTLV()
        .also { if (it.size != 1) throw ImplementationError("DER serializer multiple elements") }.first()
}


/**
 * Decodes [source] DER bytes using the given [deserializer].
 *
 * @throws kotlinx.serialization.SerializationException if input bytes or descriptor/tag/nullability constraints are invalid
 */
@ExperimentalSerializationApi
@Throws(kotlinx.serialization.SerializationException::class)
fun <T> Der.decodeFromDer(source: ByteArray, deserializer: DeserializationStrategy<T>): T {
    val layoutPlan = DerLayoutPlanContext(configuration).also { it.prime(deserializer.descriptor) }
    val decoder = DerDecoder(
        Buffer().also { it.write(source) },
        serializersModule = configuration.serializersModule,
        formatConfiguration = configuration,
        layoutPlan = layoutPlan,
    )
    return decoder.decodeSerializableValue(deserializer)
}

/**
 * Decodes a single TLV [source] using the given [deserializer].
 *
 * @throws kotlinx.serialization.SerializationException if descriptor/tag/nullability constraints are violated
 */
@ExperimentalSerializationApi
@Throws(kotlinx.serialization.SerializationException::class)
fun <T> Der.decodeFromTlv(source: Asn1Element, deserializer: DeserializationStrategy<T>): T {
    val layoutPlan = DerLayoutPlanContext(configuration).also { it.prime(deserializer.descriptor) }
    val decoder = DerDecoder(
        listOf(source),
        serializersModule = configuration.serializersModule,
        formatConfiguration = configuration,
        layoutPlan = layoutPlan,
    )
    return decoder.decodeSerializableValue(deserializer)
}
