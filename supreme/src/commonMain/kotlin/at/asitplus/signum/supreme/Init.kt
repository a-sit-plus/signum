package at.asitplus.signum.supreme

import at.asitplus.signum.indispensable.digest.DigestOperationProvider
import at.asitplus.signum.indispensable.integrity.SignatureVerifierProvider
import at.asitplus.signum.indispensable.kdf.KDFOperationProvider
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.Indispensable
import at.asitplus.signum.indispensable.Indispensable.init
import at.asitplus.signum.supreme.hash.SupremeDigestProvider
import at.asitplus.signum.supreme.kdf.SupremeKDFProvider
import at.asitplus.signum.supreme.sign.SupremeKotlinVerifierProvider
import at.asitplus.signum.supreme.sign.SupremePlatformVerifierProvider

/** NEVER CALL THIS DIRECTLY -> use [Supreme.init] */
internal expect fun supremePlatformInit()
object Supreme {
    private val initialize by lazy {
        ServiceLoader.register<SignatureVerifierProvider>(SupremePlatformVerifierProvider)
        ServiceLoader.register<SignatureVerifierProvider>(SupremeKotlinVerifierProvider)
        ServiceLoader.register<DigestOperationProvider>(SupremeDigestProvider)
        ServiceLoader.register<KDFOperationProvider>(SupremeKDFProvider)
        supremePlatformInit()
    }
    // this should be replaced by sweetspi
    fun init() {
        initialize
    }
}
