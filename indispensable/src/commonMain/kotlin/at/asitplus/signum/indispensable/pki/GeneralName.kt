package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.WithSourceRepresentation

/** An encoding-independent RFC 5280/C509 `GeneralName`. */
interface GeneralName : WithSourceRepresentation {
    /**
     * Returns whether this name is valid:
     * - `true`: validation succeeded
     * - `false`: validation failed
     * - `null`: no validation implemented (the generic [GeneralName] never validates)
     */
    val isValid: Boolean? get() = null

    @SignumInternals
    class Unknown(lookupResult: UnsupportedCryptoException)
        : GeneralName, ServiceLoader.UnknownShim(lookupResult)

    companion object
}

interface GeneralNameFormatProvider {
    fun decodeFromAsn1(generalName: X509GeneralName): GeneralName?
    fun encodeToAsn1(generalName: GeneralName): X509GeneralName?
}
