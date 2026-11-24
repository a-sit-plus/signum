package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.SignumEncodingHelpers
import at.asitplus.signum.indispensable.WithSourceRepresentation

/** An encoding-independent RFC 5280/C509 `GeneralName`. */
interface GeneralName : WithSourceRepresentation {
    @SignumInternals
    class Unknown internal constructor(source: Any, lookupResult: UnsupportedCryptoException)
        : GeneralName, ServiceLoader.UnknownShim(source, lookupResult)

    companion object {
        /** Decode a wire value and retain it as opaque if decoding is unsupported. */
        @OptIn(SignumInternals::class)
        fun <Source : Any> decodeFrom(
            source: Source,
            decode: (Source) -> GeneralName,
        ): GeneralName = SignumEncodingHelpers.decodeFrom(decode, ::Unknown)(source)
    }
}

interface GeneralNameFormatProvider {
    fun decodeFromAsn1(generalName: X509GeneralName): GeneralName?
    fun encodeToAsn1(generalName: GeneralName): X509GeneralName?

    /** Refine an exhausted lookup, retaining the supplied fallback's source storage. */
    @SignumInternals
    fun refineUnknownAsn1(source: X509GeneralName, fallback: GeneralName.Unknown): GeneralName? = null
}
