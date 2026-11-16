@file:OptIn(SignumInternals::class)

package at.asitplus.signum

import at.asitplus.awesn1.serialization.DER
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

/**
 * Application-wide providers and DER configuration.
 * Configure serializers during startup, before first [Der] access.
 * Provider-only registration remains mutable and later providers take precedence.
 * See docs/docs/extensibility.md for registration order and the single-configuration limitation.
 */
object Signum {
    init { installIndispensable() }
    private var template: Der? = null
    private val contributors = mutableListOf<SerializersModule>()
    private var consumed = false

    /**
     * Select a configuration template before serializer registration. Its settings and serializers
     * are retained in a new instance, combined with Signum's serializers and subsequent contributions.
     * Omitting this call uses awesn1's finalized default [DER] as the template, even if it was already used.
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

    /**
     * The finalized instance used by every Signum DER codec and helper. First access seals registration.
     * If no template was selected with [setDer], awesn1's default [DER] supplies the settings and serializers.
     */
    val Der: Der by lazy {
        consumed = true
        val selected = template ?: DER
        var module = selected.serializersModule
        contributors.forEach { module = module.overwriteWith(it) }
        DER {
            encodeDefaults = selected.configuration.encodeDefaults
            explicitNulls = selected.configuration.explicitNulls
            maxInputLength = selected.configuration.maxInputLength
            maxNestingDepth = selected.configuration.maxNestingDepth
            serializersModule = module
        }
    }

    /** Register every supported core/platform provider interface and optional wire serializers. */
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
        if (provider is AttributeTypeAndValueProvider) { ServiceLoader.register<AttributeTypeAndValueProvider>(provider); matched = true }
        if (provider is AttributeTypeAndValueAsn1Provider) { ServiceLoader.register<AttributeTypeAndValueAsn1Provider>(provider); matched = true }
        if (provider is CsrAttributeAsn1Provider) { ServiceLoader.register<CsrAttributeAsn1Provider>(provider); matched = true }
        if (provider is CertificateExtensionProvider) { ServiceLoader.register<CertificateExtensionProvider>(provider); matched = true }
        if (provider is GeneralNameFormatProvider) { ServiceLoader.register<GeneralNameFormatProvider>(provider); matched = true }
        matched = registerIndispensablePlatformProvider(provider) || matched
        require(matched) { "No supported provider interface on ${provider::class.simpleName}; use ServiceLoader.register<ServiceInterface> for module-specific services" }
        serializers?.let(::registerAsn1Serializers)
    }

}
