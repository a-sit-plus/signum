package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.sourceRepresentationFor
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.signum.indispensable.pki.x500.GeneralNameSerializer
import at.asitplus.signum.indispensable.pki.extn.GeneralSubtree
import kotlinx.serialization.Serializable

/** X.509 wire shape; explicit ASN.1 serializers belong here, not on the semantic GeneralSubtree. */
@Serializable
internal data class X509GeneralSubtree(
    @Serializable(with = GeneralNameSerializer::class) val base: GeneralName,
    @Asn1Tag(0u) val minimum: Asn1Integer? = null,
    @Asn1Tag(1u) val maximum: Asn1Integer? = null,
)

internal val GeneralSubtree.asn1Representation: X509GeneralSubtree
    get() = sourceRepresentationFor(X509) as? X509GeneralSubtree
        ?: X509GeneralSubtree(base, minimum.takeUnless { it == Asn1Integer(0) }, maximum)

internal fun GeneralSubtree.Companion.fromAsn1Representation(src: X509GeneralSubtree): GeneralSubtree =
    GeneralSubtree(src.base, src.minimum ?: Asn1Integer(0), src.maximum, X509 to src)
