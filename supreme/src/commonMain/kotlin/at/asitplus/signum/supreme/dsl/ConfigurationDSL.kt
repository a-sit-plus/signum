package at.asitplus.signum.supreme.dsl

import kotlin.reflect.KClass
import kotlin.reflect.KProperty

/**
 * The meta functionality that enables us to easily create DSLs.
 * @see at.asitplus.signum.supreme.dsl.DSLInheritanceDemonstration
 * @see at.asitplus.signum.supreme.dsl.DSLVarianceDemonstration
 */
object DSL {
    /** Resolve a DSL lambda to a concrete configuration */
    fun <S: DSL.Data, T: S> resolve(factory: ()->T, config: DSLConfigureFn<S>): T =
        (if (config == null) factory() else factory().apply(config)).also(DSL.Data::doValidate)

    /** A collection of equivalent DSL configuration structures which shadow each other.
     * @see getProperty */
    class ConfigStack<S: DSL.Data>(private vararg val stackedData: S): Iterable<S> by stackedData.asIterable() {
        /** Retrieve a property from a stack of (partially-)configured DSL data.
         * Each element of the stack should have an indication of whether the property is set, and a value of the property (which is only accessed if the property is set).
         * This is commonly implemented using `lateinit var`s (with `internal val .. get() = this::prop.isInitialized` as the property checker).*/
        fun <T> getProperty(getter: (S)->T, checker: (S)->Boolean, default: ()->T): T =
            try { getter(stackedData.first(checker)) } catch (_: NoSuchElementException) { default() }
        fun <T> getProperty(getter: (S)->T, checker: (S)->Boolean, default: T) =
            try { getter(stackedData.first(checker)) } catch (_: NoSuchElementException) { default }
        fun <T> getProperty(getter: (S)->Data.Stackable<T>, default: ()->T) : T {
            for (e in stackedData) { val d = getter(e); if (d.isSet) return d.value }; return default() }
        fun <T> getProperty(getter: (S)->Data.Stackable<T>, default: T): T {
            for (e in stackedData) { val d = getter(e); if (d.isSet) return d.value }; return default }
    }

    sealed interface Holder<out T> {
        val v: T
    }

    sealed interface Invokable<out Storage, out Target: Any>: Holder<Storage> {
        operator fun invoke(configure: Target.()->Unit)
    }

    /** Constructed by: [DSL.Data.childOrDefault] and [DSL.Data.childOrNull]. */
    class DirectHolder<out T: DSL.Data?> internal constructor(default: T, private val factory: ()->(T & Any))
        : Invokable<T,T&Any> {
        private var _v: T = default
        override val v: T get() = _v

        override operator fun invoke(configure: (T & Any).()->Unit) { _v = resolve(factory, configure) }
    }

    sealed interface Option<out ResultT: DSL.Data?, out InvokeT: ResultT&Any> : Invokable<ResultT, InvokeT>
    class MainOption<ResultT: DSL.Data?, InvokeT: ResultT&Any>(private val factory: ()->InvokeT, default: ResultT)
        : Option<ResultT, InvokeT> {
        private var _v: ResultT = default
        override val v get() = _v
        override operator fun invoke(configure: InvokeT.()->Unit) { _v = resolve(factory, configure) }

        inner class Alternate<AlternateInvokeT: ResultT&Any>(private val factory: ()->AlternateInvokeT)
            :Option<ResultT, AlternateInvokeT>
        {
            override val v get() = this@MainOption.v
            override operator fun invoke(configure: AlternateInvokeT.()->Unit) { this@MainOption._v = resolve(factory, configure) }
            internal val parent get() = this@MainOption
        }
    }

    /** Constructed by: [DSL.Data.integratedReceiver]. */
    class Integrated<T: Any>(): Invokable<(T.()->Unit)?, T> {
        private var _v: (T.()->Unit)? = null
        override val v: (T.()->Unit)? get() = _v
        override operator fun invoke(configure: T.()->Unit) { _v = configure }
    }

    /** Constructed by: [DSL.Data.unsupported]. */
    class Unsupported<T: Any> internal constructor(val error: String): Invokable<Unit, T> {
        override val v: Unit get() = Unit
        override fun invoke(configure: T.() -> Unit) { throw UnsupportedOperationException(error); }

        operator fun getValue(thisRef: Any?, property: KProperty<*>): Nothing { throw UnsupportedOperationException(error) }
        operator fun setValue(thisRef: Any?, property: KProperty<*>, value: Any) { throw UnsupportedOperationException(error) }
    }

    @DslMarker
    annotation class Marker

    /** The superclass of all DSL configuration objects. Exposes helper functions for definition. */
    @Marker
    open class Data {
        /**
         * Embeds an optional child. Use as `val sub = childOrNull(::TypeOfSub)`.
         * Defaults to `null`.
         *
         * User code will invoke as `sub { }`
         * This constructs a new child and configures it using the specified block.
         */
        protected fun <T: DSL.Data> childOrNull(factory: ()->T): Invokable<T?,T> =
            DirectHolder<T?>(null, factory)

        /**
         * Embeds an optional child. Use as `val sub = childOrDefault(::TypeOfSub) { ... }
         * Defaults to a child configured using the specified default block.
         *
         * User code will invoke as `sub { }`
         * This constructs a new child and configures it using the specified block.
         * Note that the specified default block is **not** applied if user code configures the child.
         */
        protected fun <T: DSL.Data> childOrDefault(factory: ()->T, default: (T.()->Unit)? = null): Invokable<T,T> =
            DirectHolder<T>(factory().also{ default?.invoke(it) }, factory)

        /**
         * Specifies a generalized holder of type T.
         * Use as `val option1 = firstOption(GeneralType::class, ::SpecializedType)`.
         *
         * Defaults to a default-constructed `SpecializedType`.
         *
         * Alternate options can be spun off using `val option2 = option1.alternate(::OtherSpecializedType)`
         * All alternate options share to same storage, which can be accessed using [Option.v] on any of them.
         */
        protected fun <T: DSL.Data, S: T> firstOption(cls: KClass<T>, factory: ()->S): Option<T,S> =
            MainOption<T,S>(factory, factory())

        /**
         * Specifies a generalized holder of type T.
         * Use as `val option1 = firstOptionWithDefault(GeneralType::class, ::SpecializedType) { foo = true }`.
         *
         * Defaults to a `SpecializedType` configured using the specified default block.
         * Note that the specified default block is **not** applied if user code explicitly configures this element.
         *
         * Alternate options can be spun off using `val option2 = option1.alternate(::OtherSpecializedType)`
         * All alternate options share to same storage, which can be accessed using [Option.v] on any of them.
         */
        protected fun <T: DSL.Data, S: T> firstOptionWithDefault(cls: KClass<T>, factory: ()->S, default: (S.()->Unit)): Option<T,S> =
            MainOption<T,S>(factory, factory().also(default).also(DSL.Data::doValidate))

        /**
         * Specifies a generalized holder of type T.
         * Use as `val option1 = firstOptionOfOptional(GeneralType::class, ::SpecializedType)`.
         *
         * Defaults to `null`.
         *
         * Alternate options can be spun off using `val option2 = option1.alternate(::OtherSpecializedType)`
         * All alternate options share to same storage, which can be accessed using [Option.v] on any of them.
         */
        protected fun <T: DSL.Data, S: T> firstOptionOfOptional(cls: KClass<T>, factory: ()->S): Option<T?,S> =
            MainOption<T?,S>(factory, null)

        protected fun <ResultT: DSL.Data?, InvokeT: ResultT&Any> Option<ResultT,*>.alternate(factory: ()->InvokeT): Option<ResultT, InvokeT> =
            when(this) {
                is MainOption<ResultT,*> -> this.Alternate(factory)
                is MainOption<ResultT,*>.Alternate<*> -> this.parent.Alternate(factory)
            }

        /**
         * Integrates an external configuration lambda into the DSL.
         * Use as `val other = integratedReceiver<ExternalType>()`.
         *
         * This receiver can be invoked, but simply stores the received lambda instead of running it.
         * Defaults to `null`.
         */
        protected fun <T: Any> integratedReceiver(): Integrated<T> =
            Integrated<T>()

        /**
         * Marks an inherited DSL substructure as unsupported. Attempts to use it throw [UnsupportedOperationException]. Use very sparingly.
         */
        protected fun <T: Any> unsupported(why: String): Unsupported<T> =
            Unsupported<T>(why)

        /**
         * Convenience delegate for multiple points of configuration DSLs.
         * It keeps track of whether the value has been explicitly set, and is compatible with [ConfigStack.getProperty].
         *
         * Use as `internal val _foo = Stackable<Int>(); var foo by _foo`, then access as `stack.getProperty(DSLType::_foo, default = 42)`.
         */
        class Stackable<T>() {
            private var _storage: T? = null
            @Suppress("UNCHECKED_CAST")
            internal val value: T get() { check(isSet); return _storage as T }
            internal var isSet: Boolean = false
            operator fun getValue(thisRef: Data, property: KProperty<*>): T { return value }
            operator fun setValue(thisRef: Data, property: KProperty<*>, v: T) { _storage = v; isSet = true; }

        }

        /**
         * Invoked by `DSL.resolve()` after the configuration block runs.
         * Can be used for sanity checks.
         */
        protected open fun validate() {}

        internal fun doValidate() = validate()
    }
}

typealias DSLConfigureFn<T> = (T.()->Unit)?
