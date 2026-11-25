package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.WithSourceRepresentation
import kotlin.jvm.JvmSynthetic

/** An encoding-independent RFC 5280/C509 `GeneralName`. */
interface GeneralName : WithSourceRepresentation {
    @SignumInternals
    class Unknown private constructor(
        source: X509GeneralName,
        lookupResult: UnsupportedCryptoException,
    ) : GeneralName, ServiceLoader.UnknownShim(source, lookupResult) {
        companion object {
            @JvmSynthetic
            internal fun fromSource(source: X509GeneralName, lookupResult: UnsupportedCryptoException) =
                Unknown(source, lookupResult)
        }
    }

    companion object
}

interface GeneralNameFormatProvider {
    fun decodeFromAsn1(generalName: X509GeneralName): GeneralName?
    fun encodeToAsn1(generalName: GeneralName): X509GeneralName?

    /**
     * Internal coordination for PKIX. [defer] records the specialized lookup failure and supplies
     * a factory that receives the full diagnostic if the remaining general-name providers decline.
     */
    @SignumInternals
    @JvmSynthetic
    fun decodeOtherNameForLookup(
        source: X509GeneralName.Other,
        defer: (UnsupportedCryptoException, (UnsupportedCryptoException) -> GeneralName) -> Nothing,
    ): GeneralName? = decodeFromAsn1(source)
}

@OptIn(SignumInternals::class)
internal fun decodeAsn1GeneralName(source: X509GeneralName): GeneralName {
    val providers = ServiceLoader.load<GeneralNameFormatProvider>()
    if (source !is X509GeneralName.Other) {
        return providers.getWithUnknown(source, GeneralName.Unknown::fromSource, GeneralNameFormatProvider::decodeFromAsn1)
    }

    var opaque: ((UnsupportedCryptoException) -> GeneralName)? = null
    return try {
        providers.get(source) {
            decodeOtherNameForLookup(it) { failure, fallback ->
                opaque = fallback
                throw failure
            }
        }
    } catch (failure: UnsupportedCryptoException) {
        opaque?.invoke(failure) ?: GeneralName.Unknown.fromSource(source, failure)
    }
}
