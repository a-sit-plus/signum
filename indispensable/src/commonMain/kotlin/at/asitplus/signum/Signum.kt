package at.asitplus.signum

import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.indispensable.installIndispensable
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

}
