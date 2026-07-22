package at.asitplus.signum.supreme

import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.supreme.os.JKSSigningKeyCreationProvider
import at.asitplus.signum.supreme.os.SupremeJKSSignerCreationProvider

internal actual fun supremePlatformInit() {
    ServiceLoader.register<JKSSigningKeyCreationProvider>(SupremeJKSSignerCreationProvider)
}
