@file:OptIn(SignumInternals::class)

package at.asitplus.signum

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.DefaultDer
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.digest.Asn1DigestAlgorithmProvider
import at.asitplus.signum.indispensable.digest.DigestOperationProvider
import at.asitplus.signum.indispensable.kdf.KDFOperationProvider
import at.asitplus.signum.indispensable.kdf.KDFProvider
import at.asitplus.signum.indispensable.mac.Asn1MACAlgorithmProvider
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCodeOperationProvider
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.sign.Asn1SignatureAlgorithmProvider
import at.asitplus.signum.indispensable.sign.InMemoryKeysProvider
import at.asitplus.signum.indispensable.sign.SignatureVerifierProvider
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.overwriteWith
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * Application-wide providers, semantic descriptors, and DER configuration.
 * Configure on one thread during startup, before first use. Descriptor registries seal on first lookup;
 * serializer contributions seal on first [Der] access. Provider-only registration remains mutable.
 * See docs/docs/default-der.md for registration order and the single-configuration limitation.
 */
object Signum {
    init { installIndispensable() }
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
        var module = SerializersModule {}
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

    /** Register every supported core/platform provider interface, plus its concrete ASN.1 adapters. */
    // TODO remove this (at least for providers)
    fun register(provider: Any, serializers: SerializersModule? = null) {
        if (serializers != null) check(!consumed) { "Register serializers before first Signum.Der use" }
        var matched = false
        if (provider is Asn1DigestAlgorithmProvider) { ServiceLoader.register<Asn1DigestAlgorithmProvider>(provider); matched = true }
        if (provider is DigestOperationProvider) { ServiceLoader.register<DigestOperationProvider>(provider); matched = true }
        if (provider is Asn1MACAlgorithmProvider) { ServiceLoader.register<Asn1MACAlgorithmProvider>(provider); matched = true }
        if (provider is MessageAuthenticationCodeOperationProvider) { ServiceLoader.register<MessageAuthenticationCodeOperationProvider>(provider); matched = true }
        if (provider is KDFProvider) { ServiceLoader.register<KDFProvider>(provider); matched = true }
        if (provider is KDFOperationProvider) { ServiceLoader.register<KDFOperationProvider>(provider); matched = true }
        if (provider is Asn1SignatureAlgorithmProvider) { ServiceLoader.register<Asn1SignatureAlgorithmProvider>(provider); matched = true }
        if (provider is SignatureFormatProvider) { ServiceLoader.register<SignatureFormatProvider>(provider); matched = true }
        if (provider is Asn1PublicKeyFormatProvider) { ServiceLoader.register<Asn1PublicKeyFormatProvider>(provider); matched = true }
        if (provider is Asn1PrivateKeyFormatProvider) { ServiceLoader.register<Asn1PrivateKeyFormatProvider>(provider); matched = true }
        if (provider is InMemoryKeysProvider) { ServiceLoader.register<InMemoryKeysProvider>(provider); matched = true }
        if (provider is SignatureVerifierProvider) { ServiceLoader.register<SignatureVerifierProvider>(provider); matched = true }
        if (provider is CertificateExtensionProvider) { ServiceLoader.register<CertificateExtensionProvider>(provider); matched = true }
        if (provider is GeneralNameFormatProvider) { ServiceLoader.register<GeneralNameFormatProvider>(provider); matched = true }
        matched = registerIndispensablePlatformProvider(provider) || matched
        require(matched) { "No supported provider interface on ${provider::class.simpleName}; use ServiceLoader.register<ServiceInterface> for module-specific services" }
        serializers?.let(::registerAsn1Serializers)
    }

    /** Register the descriptor and its concrete contextual ASN.1 serializer together. */
    inline fun <reified T : AttributeTypeAndValue> register(descriptor: AttributeTypeAndValue.Descriptor<T>) {
        Attributes.register(descriptor, SerializersModule {
            contextualAsn1(T::class, X500AttributeTypeAndValue.serializer(),
                // TODO
                { it.asn1.toRepresentation() }, { descriptor.fromValue(it.value).apply { finangleSourceRepresentation(it) } })
        })
    }
    fun attributeDescriptorFor(oid: ObjectIdentifier): AttributeTypeAndValue.Descriptor<*>? = Attributes.descriptorFor(oid)
    fun attributeDescriptorForName(name: String): AttributeTypeAndValue.Descriptor<*>? = Attributes.descriptorForName(name)
    fun attributeOidFor(name: String): ObjectIdentifier? = Attributes.oidFor(name)
    fun attributeNameFor(oid: ObjectIdentifier): String? = Attributes.nameFor(oid)
    fun registerAttributeAlias(alias: String, oid: ObjectIdentifier) = Attributes.registerAlias(alias, oid)

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
