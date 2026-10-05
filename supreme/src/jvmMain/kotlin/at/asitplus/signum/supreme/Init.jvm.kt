package at.asitplus.signum.supreme

import at.asitplus.signum.Signum
import at.asitplus.signum.supreme.os.JavaKeyStoreOperationsProvider
import at.asitplus.signum.supreme.os.SupremeJKSOperationsProvider

internal actual fun supremePlatformInit2() {
    Signum.registerProvider<JavaKeyStoreOperationsProvider>(SupremeJKSOperationsProvider)
}
