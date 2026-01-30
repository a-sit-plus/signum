package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Bool
import at.asitplus.signum.indispensable.asn1.encoding.decodeToBoolean

/**
 * X.509 Certificate Extension
 */
@ConsistentCopyVisibility
data class X509CertificateExtension @Throws(Asn1Exception::class) private constructor(
    override val oid: ObjectIdentifier,
    val value: Asn1Element,
    val critical: Boolean, //TODO replace this mess with the two properties a nullable Boolean, such that:
    val isCursed: Boolean, //true = true, false= cursed, null = false. never expose nullable, but only non-cursed true/False
    //maybe even go as far and store a single byte because there will be implementations that mess this up and encode true as 0x01
    //but supporting this mess should come with a switch
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    init {
        if (value.tag != Asn1Element.Tag.OCTET_STRING) throw Asn1TagMismatchException(
            Asn1Element.Tag.OCTET_STRING,
            value.tag
        )
    }

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1EncapsulatingOctetString
    ) : this(oid, value, critical, isCursed = false)

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1PrimitiveOctetString
    ) : this(oid, value, critical, isCursed = false)

    override fun encodeToTlv() = Asn1.Sequence {
        +oid
        if (critical) +Bool(true) else if (isCursed) +Bool(false)
        +value
    }

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): X509CertificateExtension = src.decodeRethrowing {

            val id = next().asPrimitive().readOid()
            val crit = peek()!!
            var critical = false
            var cursed = false
            if (crit.tag == Asn1Element.Tag.BOOL) {
                    critical = next().asPrimitive().decodeToBoolean()
                    if (!critical) cursed = true
            }

            val value = next()
            X509CertificateExtension(id, value, critical, cursed)
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