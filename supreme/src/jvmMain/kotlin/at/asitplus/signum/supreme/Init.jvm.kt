package at.asitplus.signum.supreme

import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.supreme.os.JavaKeyStoreOperationsProvider
import at.asitplus.signum.supreme.os.SupremeJKSOperationsProvider

internal actual fun supremePlatformInit() {
    ServiceLoader.register<JavaKeyStoreOperationsProvider>(SupremeJKSOperationsProvider)
}
