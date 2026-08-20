package at.asitplus.signum.supreme

import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.digest.DigestOperationProvider
import at.asitplus.signum.supreme.hash.SupremeIosDigestProvider
import at.asitplus.signum.supreme.sign.InMemoryKeysProvider
import at.asitplus.signum.supreme.sign.SupremeIosInMemoryKeysProvider

internal actual fun supremePlatformInit() {
    ServiceLoader.register<DigestOperationProvider>(SupremeIosDigestProvider)
    ServiceLoader.register<InMemoryKeysProvider>(SupremeIosInMemoryKeysProvider)
}
