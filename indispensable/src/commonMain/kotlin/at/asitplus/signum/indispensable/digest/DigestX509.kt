package at.asitplus.signum.indispensable.digest

import at.asitplus.awesn1.crypto.*
import at.asitplus.awesn1.crypto.pki.*
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.awesn1.Asn1Exception

val Digest.asn1Representation: X509AlgorithmIdentifier
    get() = representations[X509] as? X509AlgorithmIdentifier
        ?: (this as? WellKnownDigest)?.let { X509AlgorithmIdentifier(it.oid, null) }
        ?: throw Asn1Exception("No X.509 representation for ${this::class.simpleName}")

