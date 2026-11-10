@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.WithSourceRepresentation
import at.asitplus.signum.indispensable.pki.extn.PolicyQualifierInfo
import at.asitplus.signum.indispensable.pki.x500.DirectoryName
import at.asitplus.signum.indispensable.pki.x500.OtherName
import at.asitplus.signum.indispensable.pki.x500.X400AddressName

/** A recognized PKIX value whose interpretation failed. Its source remains available for recovery. */
abstract class InvalidPkixValue(val failure: Throwable) : WithSourceRepresentation {
    @SignumInternals final override val sourceRepresentation = SourceRepresentationStorage()
    final override fun equals(other: Any?): Boolean = this === other ||
            other is InvalidPkixValue && this::class == other::class &&
            (sourceRepresentation presentAndEquals other.sourceRepresentation)
    final override fun hashCode(): Int = 31 * this::class.hashCode() + sourceRepresentation.hashCode()
    final override fun toString(): String = "${this::class.simpleName}($sourceRepresentation): ${failure.message}"
}

class InvalidCertificateExtension(
    override val oid: ObjectIdentifier,
    override val critical: Boolean,
    failure: Throwable,
) : InvalidPkixValue(failure), CertificateExtension

class InvalidGeneralName(failure: Throwable) : InvalidPkixValue(failure), GeneralName

class InvalidOtherName(override val oid: ObjectIdentifier, failure: Throwable) : InvalidPkixValue(failure), OtherName

class InvalidAttributeTypeAndValue(override val oid: ObjectIdentifier, failure: Throwable) :
    InvalidPkixValue(failure), AttributeTypeAndValue

class InvalidCsrAttribute(override val oid: ObjectIdentifier, failure: Throwable) : InvalidPkixValue(failure), CsrAttribute

class InvalidPolicyQualifierInfo(override val oid: ObjectIdentifier, failure: Throwable) :
    InvalidPkixValue(failure), PolicyQualifierInfo

/** Local interpretation failure; this does not establish certificate or certification-path validity. */
val WithSourceRepresentation.isInvalid: Boolean get() = this is InvalidPkixValue

/** PKIX interpretation status. Unsupported names and the uninterpreted X.400 carrier remain unknown. */
val GeneralName.isValid: Boolean? get() = when (this) {
    is InvalidPkixValue -> false
    is ServiceLoader.UnknownShim, is X400AddressName -> null
    is DirectoryName -> name.isValid
    else -> true
}

val AttributeTypeAndValue.isValid: Boolean? get() = when (this) {
    is InvalidPkixValue -> false
    is ServiceLoader.UnknownShim -> null
    is TextAttributeTypeAndValue -> isValidPkixAttributeText(oid, text)
    else -> true
}

val RelativeDistinguishedName.isValid: Boolean? get() = when {
    attrsAndValues.isEmpty() || attrsAndValues.map { it.oid }.distinct().size != attrsAndValues.size -> false
    attrsAndValues.any { it.isValid == false } -> false
    attrsAndValues.any { it.isValid == null } -> null
    else -> true
}

val Name.isValid: Boolean? get() = when {
    relativeDistinguishedNames.any { it.isValid == false } -> false
    relativeDistinguishedNames.any { it.isValid == null } -> null
    else -> true
}

internal fun isValidPkixAttributeText(oid: ObjectIdentifier, text: String): Boolean = when (oid) {
    AttributeTypeAndValue.Descriptor.OID.domainComponent,
    AttributeTypeAndValue.Descriptor.OID.emailAddress -> text.all { it.code < 128 }
    AttributeTypeAndValue.Descriptor.OID.countryName,
    AttributeTypeAndValue.Descriptor.OID.dnQualifier,
    AttributeTypeAndValue.Descriptor.OID.serialNumber,
    AttributeTypeAndValue.Descriptor.OID.telephoneNumber -> text.all {
        it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it in " '()+,-./:=?"
    }
    else -> true
}
