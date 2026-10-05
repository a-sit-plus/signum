package at.asitplus.signum.indispensable

import at.asitplus.signum.Signum

internal actual fun indispensablePlatformInit() {
    Signum.registerProvider<JcaMappingProvider>(FallbackToDERFormat)
    Signum.registerProvider<JcaMappingProvider>(IndispensableJcaExtensionProvider)
}

internal actual fun registerIndispensablePlatformProvider(provider: Any): Boolean {
    if (provider !is JcaMappingProvider) return false
    Signum.registerProvider<JcaMappingProvider>(provider)
    return true
}
