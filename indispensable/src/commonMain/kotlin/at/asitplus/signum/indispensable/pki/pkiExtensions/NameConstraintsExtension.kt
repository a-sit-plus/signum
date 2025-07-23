package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.nameConstraints_2_5_29_30
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

/**
 * Name Constraints Extension
 * This extension specifies permitted and excluded subtrees that require restrictions on names
 * included in certificates issued by a given CA. Applied to the subject DNs and subject ANs.
 * RFC 5280: 4.2.1.10.
 * */
class NameConstraintsExtension(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    var permitted: GeneralSubtrees? = null,
    var excluded: GeneralSubtrees? = null
) : X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        permitted: GeneralSubtrees? = null,
        excluded: GeneralSubtrees? = null
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), permitted, excluded)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {
        private val PERMITTED: ULong = 0u
        private val EXCLUDED: ULong = 1u

        override fun doDecode(src: Asn1Sequence): NameConstraintsExtension = src.decodeRethrowing {
            val base = decodeBase(src)

            if (base.oid != KnownOIDs.nameConstraints_2_5_29_30) throw Asn1StructuralException(message = "Expected NameConstraints extension (OID: ${KnownOIDs.nameConstraints_2_5_29_30}), but found OID: ${base.oid}")

            val inner = base.value.asEncapsulatingOctetString()
                .singleOrNull()
                ?.asSequence()
                ?: return NameConstraintsExtension(base)

            val (permitted, excluded) = inner.decodeRethrowing {
                if (inner.children.size > 2) throw Asn1StructuralException("Invalid NameConstraints extension found (>2 children): ${inner.toDerHexString()}")
                var permitted: GeneralSubtrees? = null
                var excluded: GeneralSubtrees? = null
                while (hasNext()) {
                    val child = next()
                    when (child.tag.tagValue) {
                        PERMITTED -> permitted = GeneralSubtrees.decodeFromTlv(child.asExplicitlyTagged())
                        EXCLUDED -> excluded = GeneralSubtrees.decodeFromTlv(child.asExplicitlyTagged())
                    }
                }
                permitted to excluded
            }
            return NameConstraintsExtension(base, permitted, excluded)
        }
    }

    @ExperimentalPkiApi
    fun mergeWith(newConstraints: NameConstraintsExtension?) {
        if (newConstraints == null) {
            return
        }

        val newExcluded = newConstraints.excluded
        if (excluded == null) {
            if (newExcluded != null) {
                excluded = newExcluded.copy()
            }
        } else {
            if (newExcluded != null) {
                excluded!!.unionWith(newExcluded)
            }
        }

        val newPermitted = newConstraints.permitted
        if (permitted == null) {
            if (newPermitted != null) {
                permitted = newPermitted.copy()
            }
        } else {
            if (newPermitted != null) {
                val toExclude = permitted!!.intersectAndReturnExclusions(newPermitted)
                if (toExclude != null) {
                    if (excluded != null) {
                        excluded!!.unionWith(toExclude)
                    } else {
                        excluded = toExclude.copy()
                    }
                }
            }
        }
    }
}

