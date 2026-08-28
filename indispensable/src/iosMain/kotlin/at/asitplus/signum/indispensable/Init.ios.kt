package at.asitplus.signum.indispensable

import at.asitplus.signum.ServiceLoader

actual fun indispensablePlatformInit() {
    ServiceLoader.register<IosExtensionProvider>(IndispensableIosExtensionProvider)
}
