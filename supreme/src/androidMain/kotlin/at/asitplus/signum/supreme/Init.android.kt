package at.asitplus.signum.supreme

import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.supreme.os.AndroidKeyStoreOperationsProvider
import at.asitplus.signum.supreme.os.SupremeAndroidKeyStoreOperationsProvider

internal actual fun supremePlatformInit() {
    ServiceLoader.register<AndroidKeyStoreOperationsProvider>(SupremeAndroidKeyStoreOperationsProvider)
}
