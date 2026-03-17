package at.asitplus.signum.internals

import kotlin.jvm.JvmInline
import kotlin.reflect.KClass

object ServiceLoader {
    private val THE_MAP = mutableMapOf<KClass<*>, MutableSet<*>>()
    @Suppress("UNCHECKED_CAST")
    private fun <T: Any> getSetFromMap(clazz: KClass<T>): MutableSet<T> =
        THE_MAP.getOrPut(clazz) { mutableSetOf<T>() } as MutableSet<T>

    // this is what sweetspi would do automatically; it's a bit of a pain right now
    @PublishedApi internal fun <T: Any> register(it: T, clazz: KClass<T>) {
        require(it::class != clazz) { "You should use register<ServiceInterface>(ServiceProviderInstantiation)"}
        getSetFromMap(clazz).add(it)
    }
    inline fun <reified T: Any> register(it: T) { register(it, T::class) }

    private class ImmutableWrapper<out T>(private val inner: Iterable<T>): Iterable<T> by inner
    @PublishedApi internal fun <T: Any> load(clazz: KClass<T>): Iterable<T> =
        getSetFromMap(clazz).let(::ImmutableWrapper)
    @Suppress("UNCHECKED_CAST")
    inline fun <reified T: Any> load(): Iterable<T> = load(T::class)
}
