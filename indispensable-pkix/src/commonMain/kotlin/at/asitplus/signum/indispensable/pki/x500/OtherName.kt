package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import kotlinx.serialization.Serializable
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.SignumEncodingHelpers.decodeFrom
import at.asitplus.signum.indispensable.pki.GeneralName

/** An open OID-selected name family. Interpreted subtypes are independent of their source format. */
abstract class OtherName : GeneralName, Identifiable {
    override val sourceRepresentation = SourceRepresentationStorage()

    internal class Unknown(
        override val oid: ObjectIdentifier,
        source: Any,
        val lookupResult: UnsupportedCryptoException,
    ) : OtherName() {
        init { decodeFrom<Any, Unknown> { this }(source) }

        override fun equals(other: Any?): Boolean =
            other is Unknown && oid == other.oid && sourceRepresentation == other.sourceRepresentation

        override fun hashCode(): Int = 31 * oid.hashCode() + sourceRepresentation.hashCode()
        override fun toString(): String = "Failed to parse ($sourceRepresentation)"
    }

    companion object {
        @OptIn(SignumInternals::class)
        operator fun invoke(value: X509GeneralName.Other): OtherName = when (val name = GeneralName.fromAsn1(value)) {
            is GeneralName.Unknown -> Unknown(value.value.oid, value, name.lookupResult)
            else -> name as OtherName
        }
    }
}

data class HardwareModuleName(val hardwareType: ObjectIdentifier, val serial: ByteArray) : OtherName() {
    override val oid get() = OID
    override fun equals(other: Any?): Boolean = other is HardwareModuleName && hardwareType == other.hardwareType && serial.contentEquals(other.serial)
    override fun hashCode(): Int = 31 * hardwareType.hashCode() + serial.contentHashCode()
    /** ASN.1 schema from [RFC 4108, Section 5](https://www.rfc-editor.org/rfc/rfc4108.html#section-5). */
    @Serializable
    internal data class Asn1Representation(val hardwareType: ObjectIdentifier, val serial: ByteArray)

    companion object { val OID = ObjectIdentifier("1.3.6.1.5.5.7.8.4") }
}

data class SmtpUtf8Mailbox(val address: String) : OtherName() {
    override val oid get() = OID
    companion object { val OID = ObjectIdentifier("1.3.6.1.5.5.7.8.9") }
}

data class MacAddressName(val address: ByteArray) : OtherName() {
    override val oid get() = OID
    init { require(address.size == 6 || address.size == 8) { "A MAC address must contain 6 or 8 octets" } }
    override fun equals(other: Any?): Boolean = other is MacAddressName && address.contentEquals(other.address)
    override fun hashCode(): Int = address.contentHashCode()
    companion object { val OID = ObjectIdentifier("1.3.6.1.5.5.7.8.12") }
}
