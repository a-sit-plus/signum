package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.GeneralName

/** An open OID-selected name family. Interpreted subtypes are independent of their source format. */
interface OtherName : GeneralName, Identifiable {
    fun createValidatedCopy(validate: (GeneralName) -> Boolean): OtherName =
        throw UnsupportedOperationException("Custom validation copies are available on OpaqueOtherName")

    companion object {
        operator fun invoke(value: X509GeneralName.Other): OtherName = GeneralName.fromAsn1(value) as OtherName
        operator fun invoke(value: X509GeneralName.Other, validate: (GeneralName) -> Boolean): OtherName =
            invoke(value).createValidatedCopy(validate)
    }
}

class OpaqueOtherName private constructor(
    override val oid: ObjectIdentifier,
    override val isValid: Boolean?,
    @property:SignumInternals override val sourceRepresentation: SourceRepresentationStorage,
) : OtherName {
    constructor(oid: ObjectIdentifier) : this(oid, null, SourceRepresentationStorage())
    @OptIn(SignumInternals::class)
    override fun createValidatedCopy(validate: (GeneralName) -> Boolean): OtherName =
        OpaqueOtherName(oid, validate(this), sourceRepresentation)
    @OptIn(SignumInternals::class)
    override fun equals(other: Any?): Boolean = this === other || other is OpaqueOtherName &&
            oid == other.oid && (sourceRepresentation presentAndEquals other.sourceRepresentation)
    @OptIn(SignumInternals::class)
    override fun hashCode(): Int = 31 * oid.hashCode() + sourceRepresentation.hashCode()
    @OptIn(SignumInternals::class)
    override fun toString(): String = "OpaqueOtherName($oid, $sourceRepresentation)"
}

data class HardwareModuleName(val hardwareType: ObjectIdentifier, val serial: ByteArray) : OtherName {
    override val oid get() = OID
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    override fun equals(other: Any?): Boolean = other is HardwareModuleName && hardwareType == other.hardwareType && serial.contentEquals(other.serial)
    override fun hashCode(): Int = 31 * hardwareType.hashCode() + serial.contentHashCode()
    companion object { val OID = ObjectIdentifier("1.3.6.1.5.5.7.8.4") }
}

data class SmtpUtf8Mailbox(val address: String) : OtherName {
    override val oid get() = OID
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    companion object { val OID = ObjectIdentifier("1.3.6.1.5.5.7.8.9") }
}

data class MacAddressName(val address: ByteArray) : OtherName {
    override val oid get() = OID
    override val isValid get() = true
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    init { require(address.size == 6 || address.size == 8) { "A MAC address must contain 6 or 8 octets" } }
    override fun equals(other: Any?): Boolean = other is MacAddressName && address.contentEquals(other.address)
    override fun hashCode(): Int = address.contentHashCode()
    companion object { val OID = ObjectIdentifier("1.3.6.1.5.5.7.8.12") }
}
