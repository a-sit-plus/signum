package at.asitplus.signum.indispensable

import at.asitplus.signum.ServiceLoader

internal actual fun indispensablePlatformInit() {
    ServiceLoader.register<JcaMappingProvider>(FallbackToDERFormat)
    ServiceLoader.register<JcaMappingProvider>(IndispensableJcaExtensionProvider)
}
