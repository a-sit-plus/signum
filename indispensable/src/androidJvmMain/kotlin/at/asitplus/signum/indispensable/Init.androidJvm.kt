package at.asitplus.signum.indispensable

import at.asitplus.signum.ServiceLoader

internal actual fun indispensablePlatformInit() {
    ServiceLoader.register<JcaMappingProvider>(FallbackToDERFormat)
    ServiceLoader.register<JcaMappingProvider>(IndispensableJcaExtensionProvider)
}

internal actual fun registerIndispensablePlatformProvider(provider: Any): Boolean {
    var matched = false
    if (provider is JcaMappingProvider) { ServiceLoader.register<JcaMappingProvider>(provider); matched = true }
    return matched
}
