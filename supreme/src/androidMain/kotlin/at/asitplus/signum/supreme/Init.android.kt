package at.asitplus.signum.supreme

import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.supreme.os.AndroidKeyStoreOperationsProvider
import at.asitplus.signum.supreme.os.SupremeAndroidKeyStoreOperationsProvider
import at.asitplus.signum.supreme.sign.InMemoryKeysProvider
import at.asitplus.signum.supreme.sign.SupremeJVMInMemoryKeysProvider

internal actual fun supremePlatformInit2() {
    ServiceLoader.register<AndroidKeyStoreOperationsProvider>(SupremeAndroidKeyStoreOperationsProvider)
}
