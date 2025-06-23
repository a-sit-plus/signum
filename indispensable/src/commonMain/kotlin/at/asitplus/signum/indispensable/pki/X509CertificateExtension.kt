package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1PrimitiveOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Bool
import at.asitplus.signum.indispensable.asn1.readOid
import at.asitplus.signum.indispensable.asn1.runRethrowing
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
    val value: Asn1Element,
    val critical: Boolean = false
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    init {
        if (value.tag != Asn1Element.Tag.OCTET_STRING) throw Asn1TagMismatchException(Asn1Element.Tag.OCTET_STRING, value.tag)
    }

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

        private val extensionDecoders: MutableMap<ObjectIdentifier, (Asn1Sequence, Asn1Element.Tag?) -> X509CertificateExtension> = mutableMapOf(
            KnownOIDs.basicConstraints_2_5_29_19 to BasicConstraintsExtension::decodeFromTlv,
            KnownOIDs.nameConstraints_2_5_29_30 to NameConstraintsExtension::decodeFromTlv,
            KnownOIDs.policyConstraints_2_5_29_36 to PolicyConstraintsExtension::decodeFromTlv,
            KnownOIDs.certificatePolicies_2_5_29_32 to CertificatePoliciesExtension::decodeFromTlv,
            KnownOIDs.policyMappings to PolicyMappingsExtension::decodeFromTlv,
            KnownOIDs.inhibitAnyPolicy to InhibitAnyPolicyExtension::decodeFromTlv
        )

        fun registerExtensionDecoder(
            oid: ObjectIdentifier,
            decoder: (Asn1Sequence, Any?) -> X509CertificateExtension
        ) {
            extensionDecoders[oid] = decoder
        }

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): X509CertificateExtension = src.decodeRethrowing {

            val id = next().asPrimitive().readOid()
            val oid = (src.children[0] as Asn1Primitive).readOid()
            return extensionDecoders[oid]?.invoke(src, null) ?: decodeBase(src)
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