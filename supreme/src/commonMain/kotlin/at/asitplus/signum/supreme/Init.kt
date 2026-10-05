package at.asitplus.signum.supreme

import at.asitplus.signum.indispensable.sign.SignatureVerifierProvider
import at.asitplus.signum.indispensable.kdf.KDFOperationProvider
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.installIndispensable
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCodeOperationProvider
import at.asitplus.signum.supreme.kdf.SupremeKDFProvider
import at.asitplus.signum.supreme.mac.SupremeHMACOperationsProvider
import at.asitplus.signum.supreme.sign.SupremeKotlinVerifierProvider

/** NEVER CALL THIS DIRECTLY -> use [Signum.installSupreme] */
internal expect fun supremePlatformInit()
private val initialize by lazy {
    Signum.installIndispensable()
    Signum.registerProvider<SignatureVerifierProvider>(SupremeKotlinVerifierProvider)
    Signum.registerProvider<KDFOperationProvider>(SupremeKDFProvider)
    Signum.registerProvider<MessageAuthenticationCodeOperationProvider>(SupremeHMACOperationsProvider)
    supremePlatformInit()
}

/** Install this module's built-in providers once, before registering overrides. */
fun Signum.installSupreme() {
    initialize
}
