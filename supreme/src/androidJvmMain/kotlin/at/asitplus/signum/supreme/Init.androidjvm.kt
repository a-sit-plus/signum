package at.asitplus.signum.supreme

import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.digest.DigestOperationProvider
import at.asitplus.signum.supreme.hash.SupremeJVMDigestProvider
import at.asitplus.signum.supreme.sign.InMemoryKeysProvider
import at.asitplus.signum.supreme.sign.SupremeJVMInMemoryKeysProvider


/** further delegation to ios/android specifics */
internal expect fun supremePlatformInit2()
internal actual fun supremePlatformInit() {
    ServiceLoader.register<DigestOperationProvider>(SupremeJVMDigestProvider)
    ServiceLoader.register<InMemoryKeysProvider>(SupremeJVMInMemoryKeysProvider)
    supremePlatformInit2()
}
