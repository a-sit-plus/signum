package at.asitplus.signum.supreme

import at.asitplus.signum.Signum
import at.asitplus.signum.supreme.os.AndroidKeyStoreOperationsProvider
import at.asitplus.signum.supreme.os.SupremeAndroidKeyStoreOperationsProvider

internal actual fun supremePlatformInit2() {
    Signum.registerProvider<AndroidKeyStoreOperationsProvider>(SupremeAndroidKeyStoreOperationsProvider)
}
