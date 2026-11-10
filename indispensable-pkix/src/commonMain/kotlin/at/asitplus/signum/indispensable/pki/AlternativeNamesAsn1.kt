package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.crypto.pki.X509GeneralNames
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.asn1Decoders
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.asn1Encoders
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1

val AlternativeNames.asn1 get() =
    asn1Encoders<X509GeneralNames,_> {
        X509GeneralNames(generalNames.map { it.asn1.toRepresentation() })
    }

val AlternativeNames.Companion.fromAsn1 get() =
    asn1Decoders<X509GeneralNames,_> { src ->
        AlternativeNames(src.entries.map { GeneralName.fromAsn1(it) })
    }
