package at.asitplus.signum.indispensable.mac

import at.asitplus.awesn1.crypto.*
import at.asitplus.awesn1.crypto.pki.*
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.awesn1.Asn1Exception

@Suppress("UNCHECKED_CAST")
val MessageAuthenticationCode.asn1Representation: X509AlgorithmIdentifier
    get() = representations[X509] as? X509AlgorithmIdentifier
        ?: throw Asn1Exception("No X.509 representation for ${this::class.simpleName}")

