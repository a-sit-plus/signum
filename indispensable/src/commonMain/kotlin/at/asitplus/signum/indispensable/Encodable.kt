@file:OptIn(SignumInternals::class)

package at.asitplus.signum.indispensable

import at.asitplus.awesn1.runRethrowing
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.internals.ImplementationError

/** Concrete instantiation of [WithSourceRepresentation] interfaces need to provide a
 * default-constructed instance of this class as an override.
 * It is used as a backing field by [SignumEncodingHelpers.encodeTo] and [SignumEncodingHelpers.decodeFrom],
 * to enable byte-for-byte round-tripping. */
class SourceRepresentationStorage {
    /** This should NEVER be touched outside of createFrom/convertTo, or all bets are off. */
    @SignumInternals
    internal var x: Any? = null
    @OptIn(SignumInternals::class)
    override fun hashCode() = x.hashCode()
    @OptIn(SignumInternals::class)
    override fun equals(other: Any?) = (other is SourceRepresentationStorage) && (x == other.x)
    @OptIn(SignumInternals::class)
    infix fun presentAndEquals(other: SourceRepresentationStorage) = (x != null) && this == other
    @OptIn(SignumInternals::class)
    override fun toString() = x.toString()
}

interface WithSourceRepresentation {
    /** The cached source representation. No, you aren't allowed to mess with it directly. Can't be `internal` because interface. */
    val sourceRepresentation: SourceRepresentationStorage
}

/** The source format that this was parsed from, if any, in human-readable form. */
@OptIn(SignumInternals::class)
val WithSourceRepresentation.sourceFormat get(): String {
    return (sourceRepresentation.x ?: return "<no source>")::class.simpleName ?: "<anonymous>"
}

/** This should NEVER be touched outside of createFrom/convertTo, or all bets are off. */
@SignumInternals @PublishedApi
internal fun WithSourceRepresentation.finangleSourceRepresentation(v: Any) {
    this.sourceRepresentation.x = v
}

/** This should NEVER be touched outside of createFrom/convertTo, or all bets are off. */
@SignumInternals @PublishedApi
internal val WithSourceRepresentation.realSourceRepresentation
    get() = this.sourceRepresentation.x

/**
 * The methods in this class are useful for extension authors that want to implement conversion to custom encodings.
 * See `X509Representations.kt`'s wrappers for usage examples, but very generally:
 * - `val YourType.toYourFormat get() = encodeTo { CustomFormatType(...) }` gives you `toYourFormat()`
 * - `val YourType.Companion.fromYourFormat get() = decodeFrom { src: CustomFormatType -> YourType(...) }`
 *    gives you `fromYourFormat()` with object round tripping for re-encoding
 *
 * If you hand off to a provider infrastructure, see `encodeWith` and `decodeWith` for more convenient forms
 * supporting the standard provider pattern.
 *
 * Recommended usage is as `import ...SignumEncodingHelpers.encodeTo` and
 * `import ...SignumEncodingHelpers.decodeFrom`.
 */
object SignumEncodingHelpers {

/** The low-level decoding function.
 * Constructs using the specified constructor lambda, then sets the source representation. */
inline fun <reified EncodedType: Any, reified AbstractType: WithSourceRepresentation> decodeFrom(
    crossinline fn: (EncodedType)->AbstractType
): (EncodedType)->AbstractType = { encoded ->
    runRethrowing { fn(encoded) }.also {
        it.realSourceRepresentation?.let { existing ->
            // heuristic: overwriting the existing representation with a different representation of the same type is a bug
            // overwriting with a different type can be legal (because of how nested calls end up working)
            // the value returned from the decodeFrom lambda must always be a FRESH instance, due to how source round-tripping works.
            // the only exception is if the decoder only accepts a single canonical representation, in which case source round-tripping can be opted out of (by making val sourceRepresentation a getter instead of a backing field.)
            if ((encoded::class == existing::class) && (encoded != existing)) {
                throw ImplementationError("Overwriting existing ${encoded::class.simpleName} source representation on an ${it::class.simpleName} (${it}) with a different instance. This is almost certainly a bug caused by reusing a singleton instance in source-format decoders.")
            }
        }
        @OptIn(SignumInternals::class) it.finangleSourceRepresentation(encoded)
    }
}

/** A high-level decoding function using a Provider.
 * Delegates to ServiceLoader to perform decoding. */
// with provider + unknown wants source type
@Suppress("BOUNDS_NOT_ALLOWED_IF_BOUNDED_BY_TYPE_PARAMETER")
inline fun <
    reified ProviderType: Any,
    reified EncodedType: Any,
    reified AbstractType: WithSourceRepresentation,
    UnknownType
> decodeWith(
    crossinline fn: ProviderType.(EncodedType)->AbstractType?,
    crossinline unknownCtor: (EncodedType, UnsupportedCryptoException)->UnknownType = { _,x -> throw x }
) : (EncodedType)->AbstractType where UnknownType : AbstractType, UnknownType : ServiceLoader.UnknownShim = decodeFrom {
    ServiceLoader.load<ProviderType>().getWithUnknown(it, unknownCtor, fn)
}

/** A high-level decoding function using a Provider.
 * Delegates to ServiceLoader to perform decoding. */
// with provider + unknown does not want source type
@Suppress("BOUNDS_NOT_ALLOWED_IF_BOUNDED_BY_TYPE_PARAMETER")
inline fun <
        reified ProviderType: Any,
        reified EncodedType: Any,
        reified AbstractType: WithSourceRepresentation,
        UnknownType
        > decodeWith(
    crossinline fn: ProviderType.(EncodedType)->AbstractType?,
    crossinline unknownCtor: (UnsupportedCryptoException)->UnknownType = { x -> throw x }
) : (EncodedType)->AbstractType where UnknownType : AbstractType, UnknownType : ServiceLoader.UnknownShim =
    decodeWith(fn, { _, x -> unknownCtor(x) })

/** The low-level encoding function.
 * Uses the cached source representation if present and matching.
 * Otherwise, calls the converter function. */
inline fun <reified EncodedType: Any, reified AbstractType: WithSourceRepresentation> AbstractType.encodeTo(
    crossinline fn: (AbstractType)->EncodedType
): EncodedType {
    @OptIn(SignumInternals::class)
    this@encodeTo.realSourceRepresentation?.let { v ->
        if (v is EncodedType) return v
    }
    return runRethrowing { fn(this@encodeTo) }
}

/** A high-level encoding function using a Provider.
 * Delegates to ServiceLoader to perform encoding (if necessary). */
inline fun <
    reified ProviderType : Any,
    reified EncodedType : Any,
    reified AbstractType : WithSourceRepresentation
> AbstractType.encodeWith(
    crossinline fn: ProviderType.(AbstractType)->EncodedType?
): EncodedType = encodeTo { ServiceLoader.load<ProviderType>().get(this, fn) }

}
