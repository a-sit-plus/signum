package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.asn1Decoders
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.asn1Encoders
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.pki.extn.GeneralSubtree
import com.ionspin.kotlin.bignum.integer.BigInteger

internal val GeneralSubtree.asn1 get() = asn1Encoders<GeneralSubtree.Asn1Representation, _> {
    GeneralSubtree.Asn1Representation(base.asn1.toRepresentation(), minimum.takeUnless { it == BigInteger.ZERO }?.toAsn1Integer(), maximum?.toAsn1Integer())
}

internal val GeneralSubtree.Companion.fromAsn1 get() = asn1Decoders<GeneralSubtree.Asn1Representation, _> {
    GeneralSubtree(GeneralName.fromAsn1(it.base), it.minimum?.toBigInteger() ?: BigInteger.ZERO, it.maximum?.toBigInteger())
}
