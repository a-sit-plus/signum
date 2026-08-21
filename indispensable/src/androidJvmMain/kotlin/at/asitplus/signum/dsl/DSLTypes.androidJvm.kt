package at.asitplus.signum.dsl

/** Not nested because it only exists on JVM (we need to see java.security.Provider) */
@JvmInline value class JCAProviderRefO(val provider: java.security.Provider): JCAProviderRef
fun JCAProviderRef.Companion.Of(provider: java.security.Provider?) =
    if (provider != null) JCAProviderRefO(provider) else JCAProviderRef.None
