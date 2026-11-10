package at.asitplus.signum.indispensable

import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.digest.Asn1DigestAlgorithmProvider
import at.asitplus.signum.indispensable.digest.IndispensableDigestsAlgorithmProviderAsn1
import at.asitplus.signum.indispensable.digest.IndispensableHMACProvider
import at.asitplus.signum.indispensable.mac.Asn1MACAlgorithmProvider
import at.asitplus.signum.indispensable.sign.*

/** NEVER CALL THIS DIRECTLY -> use [Signum.installIndispensable] */
internal expect fun indispensablePlatformInit()
internal expect fun registerIndispensablePlatformProvider(provider: Any): Boolean
private val initialize by lazy {
    ServiceLoader.register<Asn1DigestAlgorithmProvider>(IndispensableDigestsAlgorithmProviderAsn1)
    ServiceLoader.register<Asn1MACAlgorithmProvider>(IndispensableHMACProvider)
    ServiceLoader.register<Asn1SignatureAlgorithmProvider>(IndispensableAsn1SignatureAlgorithmProvider)
    ServiceLoader.register<SignatureFormatProvider>(IndispensableSignatureFormats)
    ServiceLoader.register<Asn1PublicKeyFormatProvider>(IndispensableAsn1PublicKeyFormatsProvider)
    ServiceLoader.register<Asn1PrivateKeyFormatProvider>(IndispensableAsn1PrivateKeyFormatsProvider)
    indispensablePlatformInit()
}

/** Install this module's built-in providers once, before registering overrides. */
fun Signum.installIndispensable() {
    initialize
}
