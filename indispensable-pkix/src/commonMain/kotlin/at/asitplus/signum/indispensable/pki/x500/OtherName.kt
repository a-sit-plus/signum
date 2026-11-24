package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.SignumInternals
import kotlinx.serialization.Serializable
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.GeneralName

/** An open OID-selected name family. Interpreted subtypes are independent of their source format. */
abstract class OtherName protected constructor(
    override val sourceRepresentation: SourceRepresentationStorage = SourceRepresentationStorage(),
) : GeneralName, Identifiable {
    @OptIn(SignumInternals::class)
    internal class Unknown(
        override val oid: ObjectIdentifier,
        private val fallback: GeneralName.Unknown,
    ) : OtherName(fallback.sourceRepresentation) {
        val lookupResult get() = fallback.lookupResult
        override fun equals(other: Any?): Boolean =
            other is Unknown && oid == other.oid && fallback == other.fallback

        override fun hashCode(): Int = 31 * oid.hashCode() + fallback.hashCode()
        override fun toString(): String = fallback.toString()
    }

    companion object {
        /** Decode a wire value and retain its payload if decoding is unsupported. */
        fun <Source : Any> decodeFrom(
            source: Source,
            oid: ObjectIdentifier,
            decode: (Source) -> OtherName,
        ): OtherName = GeneralName.decodeFrom(source, decode).asOtherName(oid)

        operator fun invoke(value: X509GeneralName.Other): OtherName =
            GeneralName.fromAsn1(value).asOtherName(value.value.oid)

        @OptIn(SignumInternals::class)
        private fun GeneralName.asOtherName(oid: ObjectIdentifier): OtherName =
            if (this is GeneralName.Unknown) Unknown(oid, this) else this as OtherName
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
