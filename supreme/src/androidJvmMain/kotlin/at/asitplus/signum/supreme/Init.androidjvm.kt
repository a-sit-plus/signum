package at.asitplus.signum.supreme

import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.digest.DigestOperationProvider
import at.asitplus.signum.indispensable.sign.SignatureVerifierProvider
import at.asitplus.signum.supreme.hash.SupremeJVMDigestProvider
import at.asitplus.signum.indispensable.sign.InMemoryKeysProvider
import at.asitplus.signum.supreme.sign.SupremeJVMInMemoryKeysProvider
import at.asitplus.signum.supreme.sign.SupremeJVMVerifierProvider


/** further delegation to jvm/android specifics */
internal expect fun supremePlatformInit2()
internal actual fun supremePlatformInit() {
    Signum.registerProvider<DigestOperationProvider>(SupremeJVMDigestProvider)
    Signum.registerProvider<InMemoryKeysProvider>(SupremeJVMInMemoryKeysProvider)
    Signum.registerProvider<SignatureVerifierProvider>(SupremeJVMVerifierProvider)
    supremePlatformInit2()
}
