package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.internals.orLazy
import kotlinx.serialization.KSerializer
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

/**
 * X.509 Certificate Extension
 */
sealed interface CertificateExtension : Identifiable {

    val critical: Boolean
    sealed interface X509Representable : CertificateExtension, DerEncodable<Awesn1X509CertificateExtension> {
        val derEncodedValue: ByteArray
    }

    companion object : DerDecodable<Awesn1X509CertificateExtension, X509Representable> {
        operator fun invoke(
            oid: ObjectIdentifier,
            critical: Boolean = false,
            value: ByteArray,
        ): X509Representable = X509CertificateExtension(oid, critical, value)

        operator fun invoke(
            oid: ObjectIdentifier,
            critical: Boolean = false,
            value: Asn1OctetString,
        ): X509Representable = X509CertificateExtension(oid, critical, value)


        operator fun invoke(asn1Representation: Awesn1X509CertificateExtension): X509Representable =
            X509CertificateExtension(asn1Representation)

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(
            serializer: KSerializer<Awesn1X509CertificateExtension>,
            src: Asn1Element,
            der: Der,
        ): X509Representable =
            X509CertificateExtension(der.decodeFromTlv(serializer, src))
    }
}

abstract class BaseCertificateExtension(
    override val oid: ObjectIdentifier,
) : CertificateExtension {
    override fun toString(): String = "CertificateExtension(oid=$oid)"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CertificateExtension) return false
        return oid == other.oid
    }

    override fun hashCode(): Int = oid.hashCode()
}

//we'll need a registry here, too; similar to ATV registry, because we'll want type safety
open class X509CertificateExtension private constructor(
    providedAsn1Representation: Awesn1X509CertificateExtension?,
    oid: ObjectIdentifier,
    override val critical: Boolean,
    override val derEncodedValue: ByteArray,
) : BaseCertificateExtension(oid), CertificateExtension.X509Representable {


    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: ByteArray,
    ) : this(null, oid, critical, value)

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1OctetString,
    ) : this(oid, critical, value.content)

    constructor(asn1Representation: Awesn1X509CertificateExtension) : this(
        asn1Representation,
        asn1Representation.oid,
        asn1Representation.critical,
        asn1Representation.value,
    )

    override val asn1Representation: Awesn1X509CertificateExtension by providedAsn1Representation orLazy {
        Awesn1X509CertificateExtension(oid, critical, derEncodedValue)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is X509CertificateExtension) return false
        return oid == other.oid && critical == other.critical && derEncodedValue.contentEquals(other.derEncodedValue)
    }

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + critical.hashCode()
        result = 31 * result + derEncodedValue.contentHashCode()
        return result
    }

    override fun toString(): String =
        "CertificateExtension(oid=$oid, critical=$critical, value=${derEncodedValue.contentToString()})"
}

internal fun CertificateExtension.requireX509(): CertificateExtension.X509Representable =
    this as? CertificateExtension.X509Representable
        ?: throw Asn1Exception("Certificate extension $oid has no X.509/DER representation")
