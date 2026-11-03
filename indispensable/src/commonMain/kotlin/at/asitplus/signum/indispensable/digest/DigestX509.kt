package at.asitplus.signum.indispensable.digest

import at.asitplus.signum.indispensable.installIndispensable
import at.asitplus.awesn1.crypto.*
import at.asitplus.awesn1.crypto.pki.*
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.signum.Signum

val Digest.asn1Representation: X509AlgorithmIdentifier
    get() = sourceRepresentationFor(X509) as? X509AlgorithmIdentifier ?: run {
        Signum.installIndispensable()
        Signum.load<DigestProvider>().get(this, DigestProvider::encodeToAsn1)
    }
