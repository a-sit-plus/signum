package at.asitplus.signum.dsl

import kotlin.reflect.KProperty

/**
 * The meta functionality that enables us to easily create DSLs.
 * @see at.asitplus.signum.supreme.dsl.DSLInheritanceDemonstration
 * @see at.asitplus.signum.supreme.dsl.DSLVarianceDemonstration
 */
object DSL {
    /** Resolve a DSL lambda to a concrete configuration */
    fun <S: Data, T: S> resolve(factory: ()->T, config: DSLConfigureFn<S>): T =
        (if (config == null) factory() else factory().apply(config)).also(Data::doValidate)

    /** Resolve a set of options to the chosen one (or null, if none) */
    fun <T: Data> options(vararg options: Invokable<T?,T>) =
        options.firstNotNullOfOrNull(Invokable<T?,T>::v)

    /** A collection of equivalent DSL configuration structures which shadow each other.
     * @see getProperty */
    class ConfigStack<S: Data>(private vararg val stackedData: S): Iterable<S> by stackedData.asIterable() {
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

    sealed interface Invokable<out Storage, out Target: Any> {
        val v: Storage
        operator fun invoke(configure: DSLInvocation<Target>)
    }

    /** Constructed by: [DSL.Data.childOrDefault] */
    class ChildOrDefault<out T: Data> internal constructor(
        private val storageGetter: ()->(DSLInvocation<T>?), private val storageSetter: (DSLInvocation<T>)->Unit,
        private val default: DSLConfigureFn<T>, private val factory: ()->(T)) : Invokable<T,T>
    {

        override val v: T get() = resolve(factory, storageGetter() ?: default)
        override operator fun invoke(configure: DSLInvocation<T>) { storageSetter(configure) }
    }

    /** Constructed by: [DSL.Data.childOrNull] */
    class ChildOrNull<out T: Data> internal constructor(
        private val storageGetter: ()->DSLInvocation<T>?, private val storageSetter: (DSLInvocation<T>)->Unit,
        private val factory: ()->(T)) : Invokable<T?,T>
    {

        override val v: T? get() = storageGetter()?.let { resolve(factory, it) }
        override operator fun invoke(configure: DSLInvocation<T>) { storageSetter(configure) }
    }

    /** Constructed by: [DSL.Data.subclassOf]. */
    class Generalized<T: Data> internal constructor() {

        private var storage: Pair<String, DSLInvocation<*>>? = null

        val isSet: Boolean get() = (storage != null)

        /**
         * Adds a invokable specialized accessor for the underlying generalized storage.
         * Use as `val DataType.specialized get() = _subHolder.option(::SpecializedClass).`
         *
         * User code can invoke this specialized accessor as `specialized { }`.
         * All configuration options of the same [Generalized] share a storage, and are mutually exclusive.
         * Each configuration option should have its own separate [key], which is independent of the [Generalized]'s storage key.
         *
         * Value reads will return:
         * - [S] configured by the user if this option was configured
         * - `null` if another option was configured
         * - [S] configured with [defaultConfiguration] if no option was configured
         *
         * Note that any given generalized storage should only have one default option.
         * If multiple default options are added, behavior will be unpredictable if not explicitly configured by the user.
         */
        fun <S:T> defaultOption(key: String, factory: ()->S, defaultConfiguration: S.()->Unit = {}): Invokable<S?, S> =
            ChildOrNull(
                storageGetter = @Suppress("UNCHECKED_CAST") {
                    val s = storage
                    when {
                        (s == null) -> defaultConfiguration
                        (s.first == key) -> s.second as DSLConfigureFn<S>
                        else -> null
                    }
                },
                storageSetter = {
                    storage = Pair(key, it)
                },
                factory = factory
            )

        /**
         * Adds a invokable specialized accessor for the underlying generalized storage.
         * Use as `val DataType.specialized get() = _subHolder.option(::SpecializedClass).`
         *
         * User code can invoke this specialized accessor as `specialized { }`.
         * All configuration options of the same [Generalized] share a storage, and are mutually exclusive.
         * Each configuration option should have its own separate [key], which is independent of the [Generalized]'s storage key.
         *
         * Value reads will return:
         * - [S] configured by the user if this option was configured
         * - `null` if this option was not configured
         */
        fun <S:T> option(key: String, factory: ()->S): Invokable<S?,S> =
            ChildOrNull(
                storageGetter = @Suppress("UNCHECKED_CAST") {
                    storage?.takeIf { it.first == key }?.second as DSLInvocation<S>?
                },
                storageSetter = {
                    storage = Pair(key, it)
                },
                factory = factory
            )
    }

    /** Constructed by: [DSL.Data.integratedReceiver]. */
    class Integrated<T: Any> internal constructor(
        private val storageGetter: ()->(DSLInvocation<T>?), private val storageSetter: (DSLInvocation<T>)->Unit,
    ): Invokable<DSLInvocation<T>?, T> {
        override val v: DSLInvocation<T>? get() = storageGetter()
        override operator fun invoke(configure: DSLInvocation<T>) { storageSetter(configure) }
    }

    /** Constructed by: [DSL.Data.unsupported]. */
    class Unsupported<T: Any> internal constructor(val error: String): Invokable<Nothing, T> {
        override val v: Nothing get() = throw UnsupportedOperationException(error)
        override fun invoke(configure: DSLInvocation<T>) { throw UnsupportedOperationException(error); }

        operator fun getValue(thisRef: Any?, property: KProperty<*>): Nothing { throw UnsupportedOperationException(error) }
        operator fun setValue(thisRef: Any?, property: KProperty<*>, value: Any) { throw UnsupportedOperationException(error) }
    }

    @DslMarker
    annotation class Marker

    /** The superclass of all DSL configuration objects. Exposes helper functions for definition. */
    @Marker
    open class Data {

        private val CONFIGURATION = mutableMapOf<String, DSLInvocation<*>>()

        /**
         * Embeds an optional child. Use as `val DataType.sub get() = childOrNull("STORAGE_KEY", ::TypeOfSub)`.
         * Defaults to `null`.
         *
         * User code will invoke as `sub { }`
         * When resolved, constructs a new child and configures it using the specified block.
         */
        fun <T: Data> childOrNull(key: String, factory: ()->T): Invokable<T?,T> =
            ChildOrNull<T>(
                storageGetter = @Suppress("UNCHECKED_CAST") { CONFIGURATION[key] as DSLConfigureFn<T> },
                storageSetter = { CONFIGURATION[key] = it },
                factory = factory)

        /**
         * Embeds an optional child. Use as `val DataType.sub get() = childOrDefault("STORAGE_KEY", ::TypeOfSub) { ... }
         * Defaults to a child configured using the specified default block.
         *
         * User code will invoke as `sub { }`
         * When resolved, constructs a new child and configures it using the specified block.
         * Note that the specified default block is **not** applied if user code configures the child.
         */
        fun <T: Data> childOrDefault(key: String, factory: ()->T, default: DSLConfigureFn<T> = null): Invokable<T,T> =
            ChildOrDefault<T>(
                storageGetter = @Suppress("UNCHECKED_CAST") { CONFIGURATION[key] as DSLConfigureFn<T> },
                storageSetter = { CONFIGURATION[key] = it },
                default = default,
                factory = factory
            )

        /**
         * Specifies a generalized holder of type T.
         * Use as `val _subHolder = subclassOf<GeneralTypeOfSub>("STORAGE_KEY")`.
         *
         * The generalized holder itself cannot be invoked.
         * Specialized invokable accessors can be spun off via `.option("SUBCLASS_KEY", ::SpecializedClass)`.
         * @see DSL.Generalized.option
         */
        fun <T: Data> subclassOf(key: String): Generalized<T> =
            Generalized<T>()

        /**
         * Integrates an external configuration lambda into the DSL.
         * Use as `val other = integratedReceiver<ExternalType>()`.
         *
         * This receiver can be invoked, but simply stores the received lambda instead of running it.
         * Defaults to `null`.
         */
        fun <T: Any> integratedReceiver(key: String): Integrated<T> =
            Integrated<T>(
                storageGetter = @Suppress("UNCHECKED_CAST") { CONFIGURATION[key] as DSLConfigureFn<T> },
                storageSetter = { CONFIGURATION[key] = it }
            )

        /**
         * Marks an inherited DSL substructure as unsupported. Attempts to use it throw [UnsupportedOperationException]. Use very sparingly.
         */
        fun <T: Any> unsupported(why: String): Unsupported<T> =
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

typealias DSLInvocation<T> = (T.()->Unit)
typealias DSLConfigureFn<T> = DSLInvocation<T>?
