package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.WithSourceRepresentation
import at.asitplus.signum.indispensable.fromAsn1

// @Service
interface CertificateExtensionProvider {
    fun decodeFromAsn1(asn1: X509CertificateExtension): CertificateExtension?
    fun encodeToAsn1(value: CertificateExtension): X509CertificateExtension?
}

/**
 * Certificate extension independent of its encoding format
 */
interface CertificateExtension : Identifiable, WithSourceRepresentation {

    val critical: Boolean

    /** derivators need to provide [critical] */
    @SignumInternals
    abstract class Unknown(lookupResult: UnsupportedCryptoException)
        : CertificateExtension, ServiceLoader.UnknownShim(lookupResult) {
        override val oid: ObjectIdentifier get() = fails
    }


    companion object {
        operator fun invoke(
            oid: ObjectIdentifier,
            critical: Boolean = false,
            value: ByteArray,
        ): CertificateExtension = fromAsn1(X509CertificateExtension(oid, critical, value))

        operator fun invoke(
            oid: ObjectIdentifier,
            critical: Boolean = false,
            value: Asn1OctetString,
        ): CertificateExtension = fromAsn1(X509CertificateExtension(oid, critical, value))

    }
}
