package at.asitplus.signum.supreme

import at.asitplus.signum.indispensable.integrity.SignatureVerifierProvider
import at.asitplus.signum.internals.ServiceLoader
import at.asitplus.signum.supreme.sign.SupremeKotlinVerifierProvider
import at.asitplus.signum.supreme.sign.SupremePlatformVerifierProvider

object Supreme {
    private val initialize by lazy {
        ServiceLoader.register<SignatureVerifierProvider>(SupremePlatformVerifierProvider)
        ServiceLoader.register<SignatureVerifierProvider>(SupremeKotlinVerifierProvider)
    }
    // this should be replaced by sweetspi
    fun init() {
        initialize
    }
}
