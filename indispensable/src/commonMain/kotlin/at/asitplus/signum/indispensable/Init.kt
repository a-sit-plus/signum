package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.digest.DigestProvider
import at.asitplus.signum.indispensable.digest.IndispensableDigestsProvider
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.digest.IndispensableHMACProvider
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCodeProvider
import at.asitplus.signum.indispensable.sign.SignatureAlgorithmsProvider
import at.asitplus.signum.indispensable.sign.IndispensablePrivateKeyFormatsProvider
import at.asitplus.signum.indispensable.sign.IndispensablePublicKeyFormatsProvider
import at.asitplus.signum.indispensable.sign.IndispensableSignatureAlgorithmsProvider
import at.asitplus.signum.indispensable.sign.IndispensableSignatureFormats

/** NEVER CALL THIS DIRECTLY -> use [Signum.installIndispensable] */
internal expect fun indispensablePlatformInit()
internal expect fun registerIndispensablePlatformProvider(provider: Any): Boolean
private val initialize by lazy {
    Signum.registerProvider<DigestProvider>(IndispensableDigestsProvider)
    Signum.registerProvider<MessageAuthenticationCodeProvider>(IndispensableHMACProvider)
    Signum.registerProvider<SignatureAlgorithmsProvider>(IndispensableSignatureAlgorithmsProvider)
    Signum.registerProvider<SignatureFormatProvider>(IndispensableSignatureFormats)
    Signum.registerProvider<PublicKeyFormatProvider>(IndispensablePublicKeyFormatsProvider)
    Signum.registerProvider<PrivateKeyFormatProvider>(IndispensablePrivateKeyFormatsProvider)
    indispensablePlatformInit()
}

/** Install this module's built-in providers once, before registering overrides. */
fun Signum.installIndispensable() {
    initialize
}
