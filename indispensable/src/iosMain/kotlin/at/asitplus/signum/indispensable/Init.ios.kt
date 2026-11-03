package at.asitplus.signum.indispensable

import at.asitplus.signum.Signum

actual fun indispensablePlatformInit() {
    Signum.registerProvider<IosMappingProvider>(IndispensableIosExtensionProvider)
}

internal actual fun registerIndispensablePlatformProvider(provider: Any): Boolean {
    if (provider !is IosMappingProvider) return false
    Signum.registerProvider<IosMappingProvider>(provider)
    return true
}
