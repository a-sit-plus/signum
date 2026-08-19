package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.digest.DigestProvider
import at.asitplus.signum.indispensable.digest.IndispensableDigestsProvider
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithmsProvider
import at.asitplus.signum.indispensable.sign.IndispensablePrivateKeyFormatsProvider
import at.asitplus.signum.indispensable.sign.IndispensablePublicKeyFormatsProvider
import at.asitplus.signum.indispensable.sign.IndispensableSignatureAlgorithmsProvider
import at.asitplus.signum.indispensable.sign.IndispensableSignatureFormats

/** NEVER CALL THIS DIRECTLY -> use [Indispensable.init] */
internal expect fun indispensablePlatformInit()
object Indispensable {
    private val initialize by lazy {
        ServiceLoader.register<DigestProvider>(IndispensableDigestsProvider)
        ServiceLoader.register<SignatureAlgorithmsProvider>(IndispensableSignatureAlgorithmsProvider)
        ServiceLoader.register<SignatureFormatProvider>(IndispensableSignatureFormats)
        ServiceLoader.register<PublicKeyFormatProvider>(IndispensablePublicKeyFormatsProvider)
        ServiceLoader.register<PrivateKeyFormatProvider>(IndispensablePrivateKeyFormatsProvider)
        indispensablePlatformInit()
    }
    // this should be replaced by sweetspi
    fun init() {
        initialize
    }
}
