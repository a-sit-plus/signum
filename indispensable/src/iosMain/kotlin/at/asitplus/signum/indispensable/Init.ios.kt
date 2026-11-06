package at.asitplus.signum.indispensable

import at.asitplus.signum.ServiceLoader

actual fun indispensablePlatformInit() {
    ServiceLoader.register<IosMappingProvider>(IndispensableIosExtensionProvider)
}

internal actual fun registerIndispensablePlatformProvider(provider: Any): Boolean {
    var matched = false
    if (provider is IosMappingProvider) { ServiceLoader.register<IosMappingProvider>(provider); matched = true }
    return matched
}
