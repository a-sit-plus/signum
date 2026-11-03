package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.asn1Decoders
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.asn1Encoders
import at.asitplus.signum.indispensable.pki.x500.GeneralNameSerializer
import at.asitplus.signum.indispensable.pki.extn.GeneralSubtree
import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlinx.serialization.Serializable

/** ASN.1 wire shape; semantic values and copies do not retain it as a constructor field. */
@Serializable
internal data class X509GeneralSubtree(
    @Serializable(with = GeneralNameSerializer::class) val base: GeneralName,
    @Asn1Tag(0u) val minimum: Asn1Integer? = null,
    @Asn1Tag(1u) val maximum: Asn1Integer? = null,
)

internal val GeneralSubtree.toAsn1 get() = asn1Encoders<X509GeneralSubtree, _> {
    X509GeneralSubtree(base, minimum.takeUnless { it == BigInteger.ZERO }?.toAsn1Integer(), maximum?.toAsn1Integer())
}

internal val GeneralSubtree.Companion.fromAsn1 get() = asn1Decoders<X509GeneralSubtree, _> {
    GeneralSubtree(it.base, it.minimum?.toBigInteger() ?: BigInteger.ZERO, it.maximum?.toBigInteger())
}
