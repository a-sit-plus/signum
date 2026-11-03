package at.asitplus.signum

import at.asitplus.awesn1.serialization.DefaultDer
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1Extension
import at.asitplus.nonFatalOrThrow
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.digest.*
import at.asitplus.signum.indispensable.mac.*
import at.asitplus.signum.indispensable.kdf.*
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.indispensable.pki.*
import kotlin.reflect.KClass
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.overwriteWith

/**
 * Application-wide providers, semantic descriptors, and DER configuration.
 * Configure on one thread during startup, before first use. Descriptor registries seal on first lookup;
 * serializer contributions seal on first [Der] access. Provider-only registration remains mutable.
 * See docs/docs/default-der.md for registration order and the single-configuration limitation.
 */
object Signum {
    private var template: Der? = null
    private val contributors = mutableListOf<SerializersModule>()
    private var consumed = false

    /**
     * Select a configuration template before serializer registration. Its settings and serializers
     * are retained in a new instance, combined with Signum's serializers and subsequent contributions.
     * Omitting this call uses awesn1's default DER after registering Signum's serializers there.
     */
    fun setDer(der: Der) {
        check(!consumed && template == null && contributors.isEmpty()) {
            "Select Signum's DER template once, before serializer registration or first DER use"
        }
        template = der
    }

    /** Contribute serializers during startup; later contributions replace earlier registrations. */
    fun registerAsn1Serializers(module: SerializersModule) {
        check(!consumed) { "Signum.Der has already been initialized; register serializers during startup" }
        if (module !in contributors) contributors += module
    }

    /** The finalized instance used by every Signum DER codec and helper. First access seals registration. */
    val Der: Der by lazy {
        consumed = true
        val selected = template
        var module = signumAsn1Serializers
        selected?.let { module = module.overwriteWith(it.serializersModule) }
        contributors.forEach { module = module.overwriteWith(it) }
        if (selected == null) {
            // Resolve awesn1's default only after registration, avoiding premature initialization.
            DefaultDer.register(module)
            DER
        } else {
            DER {
                encodeDefaults = selected.configuration.encodeDefaults
                explicitNulls = selected.configuration.explicitNulls
                maxInputLength = selected.configuration.maxInputLength
                maxNestingDepth = selected.configuration.maxNestingDepth
                serializersModule = module
            }
        }
    }

    private val providers = mutableMapOf<KClass<out Any>, ArrayDeque<*>>()
    @Suppress("UNCHECKED_CAST")
    private fun <T: Any> getStorageFromMap(clazz: KClass<T>): ArrayDeque<T> =
        providers.getOrPut(clazz) { ArrayDeque<T>() } as ArrayDeque<T>

    @PublishedApi internal fun <T: Any> registerProvider(it: T, clazz: KClass<T>) {
        require(it::class != clazz) { "Use Signum.registerProvider<ServiceInterface>(provider)"}
        getStorageFromMap(clazz).addFirst(it)
    }
    /** This needs the same interface as [load] will use. You cannot register for intermediate interfaces! */
    inline fun <reified T: Any> registerProvider(it: T) { registerProvider(it, T::class) }

    class ServiceProviders<out T: Any>(@PublishedApi internal val className: String, private val inner: Iterable<T>): Iterable<T> by inner {
        inline fun <reified KeyT, ResultT> get(what: KeyT, loadBlock: T.(KeyT)->(ResultT?)): ResultT {
            val failures = mutableListOf<Pair<String, Throwable?>>()
            if (none()) throw UnsupportedCryptoException("No $className is loaded. Did you forget module installation?")
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
        ServiceProviders(clazz.simpleName ?: "<anonymous>", getStorageFromMap(clazz))
    @Suppress("UNCHECKED_CAST")
    inline fun <reified T: Any> load(): ServiceProviders<T> = load(T::class)

    /** Register every supported core/platform provider interface, plus its concrete ASN.1 adapters. */
    fun register(provider: Any, serializers: SerializersModule? = null) {
        if (serializers != null) check(!consumed) { "Register serializers before first Signum.Der use" }
        installIndispensable()
        var matched = false
        if (provider is DigestProvider) { registerProvider<DigestProvider>(provider); matched = true }
        if (provider is DigestOperationProvider) { registerProvider<DigestOperationProvider>(provider); matched = true }
        if (provider is MessageAuthenticationCodeProvider) { registerProvider<MessageAuthenticationCodeProvider>(provider); matched = true }
        if (provider is MessageAuthenticationCodeOperationProvider) { registerProvider<MessageAuthenticationCodeOperationProvider>(provider); matched = true }
        if (provider is KDFProvider) { registerProvider<KDFProvider>(provider); matched = true }
        if (provider is KDFOperationProvider) { registerProvider<KDFOperationProvider>(provider); matched = true }
        if (provider is SignatureAlgorithmsProvider) { registerProvider<SignatureAlgorithmsProvider>(provider); matched = true }
        if (provider is SignatureFormatProvider) { registerProvider<SignatureFormatProvider>(provider); matched = true }
        if (provider is PublicKeyFormatProvider) { registerProvider<PublicKeyFormatProvider>(provider); matched = true }
        if (provider is PrivateKeyFormatProvider) { registerProvider<PrivateKeyFormatProvider>(provider); matched = true }
        if (provider is InMemoryKeysProvider) { registerProvider<InMemoryKeysProvider>(provider); matched = true }
        if (provider is SignatureVerifierProvider) { registerProvider<SignatureVerifierProvider>(provider); matched = true }
        matched = registerIndispensablePlatformProvider(provider) || matched
        require(matched) { "No supported provider interface on ${provider::class.simpleName}; use registerProvider<ServiceInterface> for module-specific services" }
        serializers?.let(::registerAsn1Serializers)
    }

    /** Register the descriptor and its concrete contextual ASN.1 serializer together. */
    inline fun <reified T : CertificateExtension> register(descriptor: CertificateExtension.Descriptor<T>) {
        CertificateExtensions.register(descriptor, SerializersModule {
            contextualAsn1(T::class, Awesn1Extension.serializer(),
                { requireNotNull(it.asn1Representation) }, { descriptor.fromAsn1Representation(it) })
        })
    }

    /** Register the descriptor and its concrete contextual ASN.1 serializer together. */
    inline fun <reified T : GeneralName> register(descriptor: GeneralName.Descriptor<T>) {
        GeneralNames.register(descriptor, SerializersModule {
            contextualAsn1(T::class, X509GeneralName.serializer(),
                { requireNotNull(it.asn1Representation) }, { descriptor.fromAsn1Representation(it) })
        })
    }

    /** Register the descriptor and its concrete contextual ASN.1 serializer together. */
    inline fun <reified T : AttributeTypeAndValue> register(descriptor: AttributeTypeAndValue.Descriptor<T>) {
        Attributes.register(descriptor, SerializersModule {
            contextualAsn1(T::class, X500AttributeTypeAndValue.serializer(),
                { requireNotNull(it.asn1Representation) }, { descriptor.fromAsn1Representation(it) })
        })
    }

    fun certificateExtensionDescriptorFor(oid: ObjectIdentifier): CertificateExtension.Descriptor<*>? = CertificateExtensions.descriptorFor(oid)
    fun generalNameDescriptorFor(tag: Asn1Element.Tag): GeneralName.Descriptor<*>? = GeneralNames.descriptorFor(tag)
    fun attributeDescriptorFor(oid: ObjectIdentifier): AttributeTypeAndValue.Descriptor<*>? = Attributes.descriptorFor(oid)
    fun attributeDescriptorForName(name: String): AttributeTypeAndValue.Descriptor<*>? = Attributes.descriptorForName(name)
    fun attributeOidFor(name: String): ObjectIdentifier? = Attributes.oidFor(name)
    fun attributeNameFor(oid: ObjectIdentifier): String? = Attributes.nameFor(oid)
    fun registerAttributeAlias(alias: String, oid: ObjectIdentifier) = Attributes.registerAlias(alias, oid)

    @OptIn(ExperimentalAtomicApi::class)
    @PublishedApi
    internal object CertificateExtensions {
        private val descriptors = mutableMapOf<ObjectIdentifier, CertificateExtension.Descriptor<*>>()
        private val sealed = AtomicReference<Map<ObjectIdentifier, CertificateExtension.Descriptor<*>>?>(null)

        @PublishedApi
        internal fun register(descriptor: CertificateExtension.Descriptor<*>, serializers: SerializersModule) {
            check(sealed.load() == null) {
                "CertificateExtension registry is sealed; register before the first (de)serialization."
            }
            Signum.registerAsn1Serializers(serializers)
            descriptors[descriptor.oid] = descriptor
        }

        fun descriptorFor(oid: ObjectIdentifier): CertificateExtension.Descriptor<*>? = view()[oid]

        private fun view(): Map<ObjectIdentifier, CertificateExtension.Descriptor<*>> =
            sealed.load() ?: descriptors.toMap().also { sealed.store(it) }
    }

    @OptIn(ExperimentalAtomicApi::class)
    @PublishedApi
    internal object GeneralNames {
        private val descriptors = mutableMapOf<Asn1Element.Tag, GeneralName.Descriptor<*>>()
        private val sealed = AtomicReference<Map<Asn1Element.Tag, GeneralName.Descriptor<*>>?>(null)

        @PublishedApi
        internal fun register(descriptor: GeneralName.Descriptor<*>, serializers: SerializersModule) {
            check(sealed.load() == null) {
                "GeneralName registry is sealed; register before the first (de)serialization."
            }
            Signum.registerAsn1Serializers(serializers)
            descriptors[descriptor.tag] = descriptor
        }

        fun descriptorFor(tag: Asn1Element.Tag): GeneralName.Descriptor<*>? = view()[tag]

        private fun view(): Map<Asn1Element.Tag, GeneralName.Descriptor<*>> =
            sealed.load() ?: descriptors.toMap().also { sealed.store(it) }
    }

    @OptIn(ExperimentalAtomicApi::class)
    @PublishedApi
    internal object Attributes {
        private val descriptors: MutableMap<ObjectIdentifier, AttributeTypeAndValue.Descriptor<*>> = standardX500AttributeDescriptors
            .associateByTo(mutableMapOf()) { it.oid }
        private val aliases = standardX500AttributeAliases.toMutableMap()
        private val sealed = AtomicReference<Map<ObjectIdentifier, AttributeTypeAndValue.Descriptor<*>>?>(null)

        @PublishedApi
        internal fun register(descriptor: AttributeTypeAndValue.Descriptor<*>, serializers: SerializersModule) {
            check(sealed.load() == null) {
                "AttributeTypeAndValue registry is sealed; register before the first (de)serialization."
            }
            Signum.registerAsn1Serializers(serializers)
            descriptors[descriptor.oid] = descriptor
        }

        fun registerAlias(alias: String, oid: ObjectIdentifier) {
            check(sealed.load() == null) {
                "AttributeTypeAndValue registry is sealed; register before the first (de)serialization."
            }
            require(descriptors.containsKey(oid)) { "No AttributeTypeAndValue descriptor registered for $oid." }
            val normalizedAlias = alias.uppercase()
            check(descriptors.values.none { it.canonicalName.uppercase() == normalizedAlias }) {
                "AttributeTypeAndValue alias '$alias' conflicts with a canonical name."
            }
            check(aliases[normalizedAlias].let { it == null || it == oid }) {
                "AttributeTypeAndValue alias '$alias' is already registered for ${aliases[normalizedAlias]}."
            }
            aliases[normalizedAlias] = oid
        }

        fun oidFor(name: String): ObjectIdentifier? =
            descriptorForName(name)?.oid

        fun nameFor(oid: ObjectIdentifier): String? =
            descriptorFor(oid)?.canonicalName

        fun descriptorFor(oid: ObjectIdentifier): AttributeTypeAndValue.Descriptor<*>? = view()[oid]

        fun descriptorForName(name: String): AttributeTypeAndValue.Descriptor<*>? {
            val normalizedName = name.uppercase()
            val descriptors = view()
            return aliases[normalizedName]?.let { descriptors[it] }
                ?: descriptors.values.firstOrNull { it.canonicalName.uppercase() == normalizedName }
        }

        private fun view(): Map<ObjectIdentifier, AttributeTypeAndValue.Descriptor<*>> =
            sealed.load() ?: descriptors.toMap().also { sealed.store(it) }
    }

}
