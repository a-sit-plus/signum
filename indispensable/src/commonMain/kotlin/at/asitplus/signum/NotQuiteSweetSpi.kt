@file:OptIn(SignumInternals::class)

package at.asitplus.signum

import at.asitplus.nonFatalOrThrow
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.WithSourceRepresentation
import kotlin.reflect.KClass

object ServiceLoader {
    private val THE_MAP = mutableMapOf<KClass<out Any>, ArrayDeque<*>>()
    @Suppress("UNCHECKED_CAST")
    private fun <T: Any> getStorageFromMap(clazz: KClass<T>): ArrayDeque<T> =
        THE_MAP.getOrPut(clazz) { ArrayDeque<T>() } as ArrayDeque<T>

    // this is what sweetspi would do automatically; it's a bit of a pain right now
    @PublishedApi internal fun <T: Any> register(it: T, clazz: KClass<T>) {
        require(it::class != clazz) { "You should use register<ServiceInterface>(ServiceProviderInstantiation)"}
        getStorageFromMap(clazz).addFirst(it)
    }
    /** This needs the same exact class as [get] will use. You cannot register for intermediate interfaces! */
    inline fun <reified T: Any> register(it: T) { register(it, T::class) }

    @SignumInternals
    abstract class UnknownShim internal constructor(
        source: Any,
        val lookupResult: UnsupportedCryptoException,
    ) : WithSourceRepresentation {
        final override val sourceRepresentation = SourceRepresentationStorage(lookupResult).apply { x = source }
        final override fun equals(other: Any?) = (other is UnknownShim) && (this::class == other::class) && (sourceRepresentation == other.sourceRepresentation)
        final override fun hashCode() = this::class.hashCode() * 31 + sourceRepresentation.hashCode()
        final override fun toString() = "Failed to parse (${sourceRepresentation.x?.let { it::class.simpleName }})"
        protected val fails : Nothing get() = throw lookupResult
    }

    @PublishedApi
    internal fun lookupFailure(value: Any?): UnsupportedCryptoException? =
        (value as? WithSourceRepresentation)?.sourceRepresentation?.lookupFailure

    class ServiceProviders<out T: Any>(@PublishedApi internal val className: String, private val inner: Iterable<T>): Iterable<T> by inner {
        inline fun <reified KeyT, ResultT> get(what: KeyT, loadBlock: T.(KeyT)->(ResultT?)): ResultT {
            lookupFailure(what)?.let { throw it }
            val failures = mutableListOf<Pair<String, Throwable?>>()
            if (none()) throw UnsupportedCryptoException("No $className is loaded. Did you forget init() somewhere?")
            for (provider in this) {
                try {
                    val result = provider.loadBlock(what)
                    lookupFailure(result)?.let { throw it }
                    if (result != null) return result
                    failures.add(Pair(provider::class.simpleName ?: "<anonymous>", null))
                } catch (e: Throwable) {
                    failures.add(Pair(provider::class.simpleName ?: "<anonymous>", e.nonFatalOrThrow()))
                }
            }
            val sb = StringBuilder("No loaded $className is able to handle $what.")
            for ((provider, failure) in failures) {
                sb.append('\n')
                sb.append("- $provider reports: ")
                if (failure == null) sb.append("<no explicit error; it likely did not recognize the ${KeyT::class.simpleName}>")
                else {
                    val failureMessage = failure.message
                    if (failureMessage.isNullOrEmpty()) sb.append("<it threw ${failure::class.simpleName} with no message>")
                    else {
                        val lines = failureMessage.lineSequence().iterator()
                        sb.append(lines.next())
                        lines.forEach { sb.append("\n  ").append(it) }
                    }
                }
            }
            val x = UnsupportedCryptoException(sb.toString())
            for ((_, failure) in failures) {
                failure?.let(x::addSuppressed)
            }
            throw x
        }

        inline fun <reified KeyT : Any, ResultT, UnsupportedT : ResultT> getWithUnknown(
            what: KeyT,
            unknownCtor: (KeyT, UnsupportedCryptoException) -> UnsupportedT,
            loadBlock: T.(KeyT) -> ResultT?,
        ): ResultT = try {
            get(what, loadBlock)
        } catch (failure: UnsupportedCryptoException) {
            unknownCtor(what, failure).also {
                check(lookupFailure(it) != null) { "Provider fallback must be a source-backed unknown" }
            }
        }
    }
    @PublishedApi internal fun <T: Any> load(clazz: KClass<T>): ServiceProviders<T> =
        ServiceProviders(clazz.simpleName ?: "<anonymous>", getStorageFromMap(clazz))
    @Suppress("UNCHECKED_CAST")
    inline fun <reified T: Any> load(): ServiceProviders<T> = load(T::class)
}
