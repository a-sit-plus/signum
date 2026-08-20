package at.asitplus.signum.supreme

import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.supreme.os.JavaKeyStoreOperationsProvider
import at.asitplus.signum.supreme.os.SupremeJKSOperationsProvider
import at.asitplus.signum.supreme.sign.InMemoryKeysProvider
import at.asitplus.signum.supreme.sign.SupremeJVMInMemoryKeysProvider

internal actual fun supremePlatformInit2() {
    ServiceLoader.register<JavaKeyStoreOperationsProvider>(SupremeJKSOperationsProvider)
}
