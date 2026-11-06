package at.asitplus.signum.indispensable

import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.digest.DigestProvider
import at.asitplus.signum.indispensable.digest.IndispensableDigestsProvider
import at.asitplus.signum.indispensable.digest.IndispensableHMACProvider
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCodeProvider
import at.asitplus.signum.indispensable.sign.*

/** NEVER CALL THIS DIRECTLY -> use [Signum.installIndispensable] */
internal expect fun indispensablePlatformInit()
internal expect fun registerIndispensablePlatformProvider(provider: Any): Boolean
private val initialize by lazy {
    ServiceLoader.register<DigestProvider>(IndispensableDigestsProvider)
    ServiceLoader.register<MessageAuthenticationCodeProvider>(IndispensableHMACProvider)
    ServiceLoader.register<SignatureAlgorithmsProvider>(IndispensableSignatureAlgorithmsProvider)
    ServiceLoader.register<SignatureFormatProvider>(IndispensableSignatureFormats)
    ServiceLoader.register<PublicKeyFormatProvider>(IndispensablePublicKeyFormatsProvider)
    ServiceLoader.register<PrivateKeyFormatProvider>(IndispensablePrivateKeyFormatsProvider)
    indispensablePlatformInit()
}

/** Install this module's built-in providers once, before registering overrides. */
fun Signum.installIndispensable() {
    initialize
}
