@file:OptIn(SignumInternals::class)

package at.asitplus.signum.indispensable

import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException

class SourceRepresentationStorage {
    /** This should NEVER be touched outside of createFrom/convertTo, or all bets are off. */
    @SignumInternals
    internal var x: Any? = null
    @OptIn(SignumInternals::class)
    override fun hashCode() = x.hashCode()
    @OptIn(SignumInternals::class)
    override fun equals(other: Any?) = (other is SourceRepresentationStorage) && (x == other.x)
    @OptIn(SignumInternals::class)
    override fun toString() = x.toString()
}

interface WithSourceRepresentation {
    /** The cached source representation. No, you aren't allowed to mess with it directly. Can't be `internal` because interface. */
    @SignumInternals
    val sourceRepresentation: SourceRepresentationStorage
}

@OptIn(SignumInternals::class)
/** The source format that this was parsed from, if any, in human-readable form. */
val WithSourceRepresentation.sourceFormat get(): String {
    return (sourceRepresentation.x ?: return "<no source>")::class.simpleName ?: "<anonymous>"
}

@SignumInternals @PublishedApi
/** This should NEVER be touched outside of createFrom/convertTo, or all bets are off. */
internal fun WithSourceRepresentation.finangleSourceRepresentation(v: Any) {
    this.sourceRepresentation.x = v
}

@SignumInternals @PublishedApi
/** This should NEVER be touched outside of createFrom/convertTo, or all bets are off. */
internal val WithSourceRepresentation.realSourceRepresentation get() =
    this.sourceRepresentation.x

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
    fn(encoded).also { @OptIn(SignumInternals::class) it.finangleSourceRepresentation(encoded) }
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
    return fn(this@encodeTo)
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
