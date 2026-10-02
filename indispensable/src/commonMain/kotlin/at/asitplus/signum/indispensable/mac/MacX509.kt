package at.asitplus.signum.indispensable.mac

import at.asitplus.awesn1.crypto.*
import at.asitplus.awesn1.crypto.pki.*
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.awesn1.Asn1Exception

val MessageAuthenticationCode.asn1Representation: X509AlgorithmIdentifier
    get() = representations[X509] as? X509AlgorithmIdentifier
        ?: (this as? HMAC)?.let { X509AlgorithmIdentifier(it.oid, at.asitplus.awesn1.Asn1Null) }
        ?: throw Asn1Exception("No X.509 representation for ${this::class.simpleName}")

