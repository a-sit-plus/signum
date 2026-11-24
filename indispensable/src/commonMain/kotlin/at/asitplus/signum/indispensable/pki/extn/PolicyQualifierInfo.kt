package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.SignumEncodingHelpers
import at.asitplus.signum.indispensable.WithSourceRepresentation

interface PolicyQualifierInfo : Identifiable, WithSourceRepresentation {
    @OptIn(SignumInternals::class)
    class Unknown internal constructor(
        override val oid: ObjectIdentifier,
        source: Any,
        lookupResult: UnsupportedCryptoException,
    ) : PolicyQualifierInfo, ServiceLoader.UnknownShim(source, lookupResult)

    companion object {
        /** Decode a wire value and retain it as opaque if decoding is unsupported. */
        fun <Source : Any> decodeFrom(
            source: Source,
            oid: ObjectIdentifier,
            decode: (Source) -> PolicyQualifierInfo,
        ): PolicyQualifierInfo = SignumEncodingHelpers.decodeFrom(decode) { input, failure ->
            Unknown(oid, input, failure)
        }(source)
    }
}
