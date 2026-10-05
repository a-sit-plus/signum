package at.asitplus.signum.supreme

import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.digest.DigestOperationProvider
import at.asitplus.signum.indispensable.sign.SignatureVerifierProvider
import at.asitplus.signum.supreme.hash.SupremeIosDigestProvider
import at.asitplus.signum.supreme.os.IosKeychainOperationsProvider
import at.asitplus.signum.supreme.os.SupremeIosKeychainOperationsProvider
import at.asitplus.signum.indispensable.sign.InMemoryKeysProvider
import at.asitplus.signum.supreme.sign.SupremeCCVerifierProvider
import at.asitplus.signum.supreme.sign.SupremeIosInMemoryKeysProvider

internal actual fun supremePlatformInit() {
    Signum.registerProvider<DigestOperationProvider>(SupremeIosDigestProvider)
    Signum.registerProvider<InMemoryKeysProvider>(SupremeIosInMemoryKeysProvider)
    Signum.registerProvider<SignatureVerifierProvider>(SupremeCCVerifierProvider)
    Signum.registerProvider<IosKeychainOperationsProvider>(SupremeIosKeychainOperationsProvider)
}
