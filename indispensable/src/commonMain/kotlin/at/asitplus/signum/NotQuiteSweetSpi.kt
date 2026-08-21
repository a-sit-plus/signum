package at.asitplus.signum

import at.asitplus.nonFatalOrThrow
import kotlin.reflect.KClass

object ServiceLoader {
    private val THE_MAP = mutableMapOf<KClass<out Any>, MutableSet<*>>()
    @Suppress("UNCHECKED_CAST")
    private fun <T: Any> getSetFromMap(clazz: KClass<T>): MutableSet<T> =
        THE_MAP.getOrPut(clazz) { mutableSetOf<T>() } as MutableSet<T>

    // this is what sweetspi would do automatically; it's a bit of a pain right now
    @PublishedApi internal fun <T: Any> register(it: T, clazz: KClass<T>) {
        require(it::class != clazz) { "You should use register<ServiceInterface>(ServiceProviderInstantiation)"}
        getSetFromMap(clazz).add(it)
    }
    inline fun <reified T: Any> register(it: T) { register(it, T::class) }

    class ServiceProviders<out T: Any>(@PublishedApi internal val className: String, private val inner: Iterable<T>): Iterable<T> by inner {
        inline fun <reified KeyT, ResultT> get(what: KeyT, loadBlock: T.(KeyT)->(ResultT?)): ResultT {
            val failures = mutableListOf<Pair<String, Throwable?>>()
            if (none()) throw UnsupportedCryptoException("No $className is loaded. Did you forget init() somewhere?")
            for (provider in this) {
                try {
                    val result = provider.loadBlock(what)
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
    }
    @PublishedApi internal fun <T: Any> load(clazz: KClass<T>): ServiceProviders<T> =
        ServiceProviders(clazz.simpleName ?: "<anonymous>", getSetFromMap(clazz))
    @Suppress("UNCHECKED_CAST")
    inline fun <reified T: Any> load(): ServiceProviders<T> = load(T::class)
}
