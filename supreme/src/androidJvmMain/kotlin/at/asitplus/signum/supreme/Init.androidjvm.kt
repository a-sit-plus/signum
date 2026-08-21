package at.asitplus.signum.supreme

import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.digest.DigestOperationProvider
import at.asitplus.signum.indispensable.integrity.SignatureVerifierProvider
import at.asitplus.signum.supreme.hash.SupremeJVMDigestProvider
import at.asitplus.signum.supreme.sign.InMemoryKeysProvider
import at.asitplus.signum.supreme.sign.SupremeJVMInMemoryKeysProvider
import at.asitplus.signum.supreme.sign.SupremeJVMVerifierProvider


/** further delegation to ios/android specifics */
internal expect fun supremePlatformInit2()
internal actual fun supremePlatformInit() {
    ServiceLoader.register<DigestOperationProvider>(SupremeJVMDigestProvider)
    ServiceLoader.register<InMemoryKeysProvider>(SupremeJVMInMemoryKeysProvider)
    ServiceLoader.register<SignatureVerifierProvider>(SupremeJVMVerifierProvider)
    supremePlatformInit2()
}
