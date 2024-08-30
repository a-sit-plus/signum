package at.asitplus.signum.supreme.dsl

import kotlin.reflect.KProperty

/**
 * The meta functionality that enables us to easily create DSLs.
 * @see at.asitplus.signum.supreme.dsl.DSLInheritanceDemonstration
 * @see at.asitplus.signum.supreme.dsl.DSLVarianceDemonstration
 */
object DSL {
    /** Resolve a DSL lambda to a concrete configuration */
    fun <S: DSL.Data, T: S> resolve(factory: ()->T, config: DSLConfigureFn<S>): T =
        (if (config == null) factory() else factory().apply(config)).also(DSL.Data::validate)

    /** A collection of equivalent DSL configuration structures which shadow each other.
     * @see getProperty */
    class ConfigStack<S: DSL.Data>(private vararg val stackedData: S) {
        /** Retrieve a property from a stack of (partially-)configured DSL data.
         * Each element of the stack should have an indication of whether the property is set, and a value of the property (which is only accessed if the property is set).
         * This is commonly implemented using `lateinit var`s (with `internal val .. get() = this::prop.isInitialized` as the property checker).*/
        fun <T> getProperty(getter: (S)->T, checker: (S)->Boolean, default: T): T =
            when (val it = stackedData.firstOrNull(checker)) { null -> default; else -> getter(it) }
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

    /** Constructed by: [DSL.Data.subclassOf]. */
    class Generalized<out T: DSL.Data?> internal constructor(default: T): Holder<T> {
        private var _v: T = default
        override val v: T get() = _v

        inner class option<out S:T&Any>
        /**
         * Adds a specialized invokable accessor for the underlying generalized storage.
         * Use as `val specialized = _holder.option(::SpecializedClass).`
         *
         * User code can invoke this specialized accessor as `specialized { }`.
         * This constructs a new specialized child, configures it using the specified block,
         * and stores it in the underlying generalized storage.
         */
        internal constructor(private val factory: ()->S) : Invokable<T,S> {
            override val v: T get() = this@Generalized.v
            override operator fun invoke(configure: S.()->Unit) { _v = resolve(factory, configure) }
        }
    }

    /** Constructed by: [DSL.Data.integratedReceiver]. */
    class Integrated<T: Any> internal constructor(): Invokable<(T.()->Unit)?, T> {
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
         * Use as `internal val _subHolder = subclassOf<GeneralTypeOfSub>()`.
         *
         * The generalized holder itself cannot be invoked, and should be marked `internal`.
         * Defaults to `null`.
         *
         * Specialized invokable accessors can be spun off via `.option(::SpecializedClass)`.
         * @see DSL.Generalized.option
         */
        protected fun <T: DSL.Data> subclassOf(): Generalized<T?> =
            Generalized<T?>(null)
        /**
         * Specifies a generalized holder of type T.
         * Use as `internal val _subHolder = subclassOf<GeneralTypeOfSub>(SpecializedClass())`.
         *
         * The generalized holder itself cannot be invoked, and should be marked `internal`.
         * Defaults to the specified `default`.
         *
         * Specialized invokable accessors can be spun off via `.option(::SpecializedClass)`.
         * @see DSL.Generalized.option
         */
        protected fun <T: DSL.Data> subclassOf(default: T): Generalized<T> =
            Generalized<T>(default)

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
         * Invoked by `DSL.resolve()` after the configuration block runs.
         * Can be used for sanity checks.
         */
        internal open fun validate() {}
    }
}

typealias DSLConfigureFn<T> = (T.()->Unit)?
