package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Bool
import at.asitplus.signum.indispensable.pki.pkiExtensions.BasicConstraintsExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.CertificatePoliciesExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.InhibitAnyPolicyExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.NameConstraintsExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.PolicyConstraintsExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.PolicyMappingsExtension

/**
 * X.509 Certificate Extension
 */
open class X509CertificateExtension @Throws(Asn1Exception::class) private constructor(
    override val oid: ObjectIdentifier,
    open val value: Asn1Element,
    open val critical: Boolean = false
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1EncapsulatingOctetString
    ) : this(oid, value, critical)

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1PrimitiveOctetString
    ) : this(oid, value, critical)

    override fun encodeToTlv() = Asn1.Sequence {
        +oid
        if (critical) +Bool(true)
        +value
    }

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): X509CertificateExtension = src.decodeRethrowing {

            val id = next().asPrimitive().readOid()
            val oid = (src.children[0] as Asn1Primitive).readOid()

            return when (oid) {
                KnownOIDs.basicConstraints_2_5_29_19 -> BasicConstraintsExtension.decodeFromTlv(src)
                KnownOIDs.nameConstraints_2_5_29_30 -> NameConstraintsExtension.decodeFromTlv(src)
                KnownOIDs.policyConstraints_2_5_29_36 -> PolicyConstraintsExtension.decodeFromTlv(src)
                KnownOIDs.certificatePolicies_2_5_29_32 -> CertificatePoliciesExtension.decodeFromTlv(src)
                KnownOIDs.policyMappings -> PolicyMappingsExtension.decodeFromTlv(src)
                KnownOIDs.inhibitAnyPolicy -> InhibitAnyPolicyExtension.decodeFromTlv(src)
                else -> decodeBase(src)
            }
        }

        @Throws(Asn1Exception::class)
        fun decodeBase(src: Asn1Sequence): X509CertificateExtension {
            val id = (src.children[0] as Asn1Primitive).readOid()
            val critical =
                if (src.children[1].tag == Asn1Element.Tag.BOOL) next().asPrimitive().content[0] == 0xff.toByte() else false

            val value = next()
            if (value.tag != Asn1Element.Tag.OCTET_STRING) throw Asn1TagMismatchException(Asn1Element.Tag.OCTET_STRING, value.tag)
            if (src.hasMoreChildren()) throw Asn1StructuralException("Invalid X509CertificateExtension found (>3 children): ${src.toDerHexString()}")
            return X509CertificateExtension(id, value, critical)
        }

    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null) return false
        if (this::class != other::class) return false

        other as X509CertificateExtension

        if (oid != other.oid) return false
        if (critical != other.critical) return false
        if (value != other.value) return false

        return true
    }

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + critical.hashCode()
        result = 31 * result + value.hashCode()
        return result
    }
}