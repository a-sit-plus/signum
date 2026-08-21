package at.asitplus.signum.dsl

import kotlin.jvm.JvmInline

/** All the ways you can specify a JCA Provider (string name, object, none); not sealed because by object only exists on JVM targets
 * @see JCAProviderRef.Of */
interface JCAProviderRef {
    @JvmInline value class ByName(val provider: String) : JCAProviderRef
    data object None : JCAProviderRef { override fun toString() = "<no JCA provider specified>" }
    companion object {
        /** Constructs a reference to the JCA provider identified by name, or no provider if string is null.
         * NB: There is also a JVM-targets-only extension on the companion that takes a JCA `Provider` object. */
        fun Of(string: String?) = if (string != null) ByName(string) else None
    }
}

class JVMEphemeralConfiguration : DSL.Data() {
    /** The JCA provider to use. Defaults to [JCAProviderRef.None] (no particular provider specified). */
    var provider: JCAProviderRef = JCAProviderRef.None
}

class VerifierConfiguration internal constructor(): DSL.Data()
val VerifierConfiguration.jvm get() =
    childOrDefault("JVM", ::JVMEphemeralConfiguration)
