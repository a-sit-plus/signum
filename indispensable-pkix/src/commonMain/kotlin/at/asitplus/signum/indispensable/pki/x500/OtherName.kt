@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.*
import kotlinx.serialization.Serializable
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.GeneralName

/**
 * An open OID-selected name family. Register ASN.1 adapters with [at.asitplus.signum.indispensable.pki.OtherNameAsn1Provider].
 * For other formats, define conversions with [SignumEncodingHelpers.decodeFrom] and [SignumEncodingHelpers.encodeTo].
 */
interface OtherName : GeneralName, Identifiable {
    class Unknown internal constructor(
        source: X509GeneralName,
        lookupResult: UnsupportedCryptoException,
    ) : OtherName, ServiceLoader.UnknownShim(source, lookupResult) {
        override val oid = (source as X509GeneralName.Other).value.oid
    }

    companion object {
        operator fun invoke(value: X509GeneralName.Other): OtherName =
            when (val decoded = GeneralName.fromAsn1(value)) {
                is OtherName -> decoded
                is GeneralName.Unknown -> Unknown(value, decoded.lookupResult)
                else -> throw UnsupportedCryptoException(
                    "Expected OtherName for OID ${value.value.oid}, received ${decoded::class.simpleName}",
                )
            }
    }
}

data class HardwareModuleName(val hardwareType: ObjectIdentifier, val serial: ByteArray) : OtherName {
    override val oid get() = OID
    override val sourceRepresentation = SourceRepresentationStorage()
    override fun equals(other: Any?): Boolean = other is HardwareModuleName && hardwareType == other.hardwareType && serial.contentEquals(other.serial)
    override fun hashCode(): Int = 31 * hardwareType.hashCode() + serial.contentHashCode()
    /** ASN.1 schema from [RFC 4108, Section 5](https://www.rfc-editor.org/rfc/rfc4108.html#section-5). */
    @Serializable
    internal data class Asn1Representation(val hardwareType: ObjectIdentifier, val serial: ByteArray)

    companion object { val OID = ObjectIdentifier("1.3.6.1.5.5.7.8.4") }
}

data class SmtpUtf8Mailbox(val address: String) : OtherName {
    override val oid get() = OID
    override val sourceRepresentation = SourceRepresentationStorage()
    companion object { val OID = ObjectIdentifier("1.3.6.1.5.5.7.8.9") }
}

data class MacAddressName(val address: ByteArray) : OtherName {
    override val oid get() = OID
    override val sourceRepresentation = SourceRepresentationStorage()
    init { require(address.size == 6 || address.size == 8) { "A MAC address must contain 6 or 8 octets" } }
    override fun equals(other: Any?): Boolean = other is MacAddressName && address.contentEquals(other.address)
    override fun hashCode(): Int = address.contentHashCode()
    companion object { val OID = ObjectIdentifier("1.3.6.1.5.5.7.8.12") }
}
